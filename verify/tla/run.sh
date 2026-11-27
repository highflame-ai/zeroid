#!/usr/bin/env bash
# Model-checks the issuance/cascade-revocation lock protocol with TLC.
#
#   verify/tla/run.sh            run every check in CHECKS below
#   verify/tla/run.sh NAME...    run only the named checks and print TLC's trace
#
# Each check names a scenario module (MC_<shape>.tla), a code variant, and what
# TLC must report: "pass", or the name of the invariant or property it must
# find violated. A check whose result differs from its expectation fails the
# run, so a check that is meant to fail keeps proving the property can fail.
# See README.md.
set -euo pipefail

TLA_VERSION=1.7.4
TLA_SHA256=936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88
TLA_URL="https://github.com/tlaplus/tlaplus/releases/download/v${TLA_VERSION}/tla2tools.jar"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cache="${XDG_CACHE_HOME:-$HOME/.cache}/zeroid-tla"
jar="$cache/tla2tools-${TLA_VERSION}.jar"

if [[ ! -f "$jar" ]] || ! echo "$TLA_SHA256  $jar" | sha256sum -c --quiet - 2>/dev/null; then
  mkdir -p "$cache"
  echo "downloading tla2tools.jar v${TLA_VERSION}"
  curl -fsSL -o "$jar.part" "$TLA_URL"
  echo "$TLA_SHA256  $jar.part" | sha256sum -c --quiet - || { echo "tla2tools.jar checksum mismatch" >&2; rm -f "$jar.part"; exit 1; }
  mv "$jar.part" "$jar"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
out="$here/out"
mkdir -p "$out"

SAFETY="TypeOK NoLiveTokenBelowRevoked NoIssuanceBelowRevoked"
LIVE="TypeOK NoRevocationFails"   # plus PROPERTIES Progress; see "Liveness" in RevocationLocks.tla

# kind inv: check the listed invariants. kind live: the listed invariants, TLC's own
# check that no state is stuck, and the Progress ranking function.
# wake: BackoffOutlastsWakeup (README, assumption 6).
#
# name                     module     variant       attempts procs wake   kind  checks                          expect
CHECKS=$(cat <<EOF
head-chain                 Chain      head          3        4     TRUE   inv   $SAFETY NoDeadlock             pass
head-mutual                Mutual     head          3        4     TRUE   inv   $SAFETY NoDeadlock             pass
head-return                Return     head          3        4     TRUE   inv   $SAFETY NoDeadlock             pass
head-samedepth             SameDepth  head          3        4     TRUE   inv   $SAFETY NoDeadlock             pass
head-residual-safety       Residual   head          3        3     TRUE   inv   $SAFETY                        pass
head-residual-deadlock     Residual   head          3        3     TRUE   inv   TypeOK NoDeadlock              NoDeadlock
head-inverted-safety       Inverted   head          3        3     TRUE   inv   $SAFETY                        pass
head-inverted-deadlock     Inverted   head          3        3     TRUE   inv   TypeOK NoDeadlock              NoDeadlock
head-chain-live            Chain      head          3        3     TRUE   live  $LIVE                          pass
head-mutual-live           Mutual     head          3        3     TRUE   live  $LIVE                          pass
head-return-live           Return     head          3        3     TRUE   live  $LIVE                          pass
head-samedepth-live        SameDepth  head          3        3     TRUE   live  $LIVE                          pass
head-residual-live         Residual   head          3        3     TRUE   live  $LIVE                          pass
head-inverted-live         Inverted   head          3        3     TRUE   live  $LIVE                          NoRevocationFails
head-residual-live-nowait  Residual   head          3        3     FALSE  live  $LIVE                          NoRevocationFails
noretry-residual-live      Residual   head          1        3     TRUE   live  $LIVE                          NoRevocationFails
noretry-inverted-live      Inverted   head          1        3     TRUE   live  $LIVE                          NoRevocationFails
round3-mutual              Mutual     round3        3        3     TRUE   inv   TypeOK NoDeadlock              NoDeadlock
round3-return              Return     round3        3        3     TRUE   inv   TypeOK NoDeadlock              NoDeadlock
round3-chain               Chain      round3        3        3     TRUE   inv   $SAFETY NoDeadlock             pass
round2-chain               Chain      round2        3        3     TRUE   inv   TypeOK NoDeadlock              NoDeadlock
main-mutual                Mutual     main          3        3     TRUE   inv   TypeOK NoDeadlock              NoDeadlock
main-chain-safety          Chain      main          3        2     TRUE   inv   $SAFETY                        NoLiveTokenBelowRevoked
no_recheck-chain           Chain      no_recheck    3        3     TRUE   inv   TypeOK NoIssuanceBelowRevoked  NoIssuanceBelowRevoked
one_snapshot-chain         Chain      one_snapshot  3        3     TRUE   inv   TypeOK NoLiveTokenBelowRevoked NoLiveTokenBelowRevoked
EOF
)

run_check() { # name module variant attempts procs wake kind expect checks...
  local name=$1 module=$2 variant=$3 attempts=$4 procs=$5 wake=$6 kind=$7 expect=$8
  shift 8
  local cfg="$work/$name.cfg"
  {
    echo "CONSTANTS"
    echo "  Variant = \"$variant\""
    echo "  Attempts = $attempts"
    echo "  MaxProcs = $procs"
    echo "  BackoffOutlastsWakeup = $wake"
    echo "  NoTok = NoTok"
    for c in Tok Parent Ident OwnerOf Depth Ord Stored0 Revoked0 Procs Kind Target Clock; do
      echo "  $c <- MC_$c"
    done
    echo "  StartIssuedAt <- MC_IssuedAt"
    echo "SPECIFICATION Spec"
    echo "INVARIANTS $*"
    if [[ $kind == inv ]]; then
      echo "VIEW view"      # the ghost `last` names the step in traces; it is not state
    else
      echo "PROPERTIES Progress"
    fi
  } >"$cfg"
  # C1 only: the C2 JIT of some OpenJDK 17 builds crashes inside TLC's evaluator.
  ( cd "$here" && java -XX:TieredStopAtLevel=1 -XX:+UseParallelGC -Djava.io.tmpdir="$work" \
      -cp "$jar" tlc2.TLC -config "$cfg" -workers auto -metadir "$work/$name.states" \
      -nowarning "MC_$module.tla" ) >"$out/$name.txt" 2>&1 || true

  local got
  if grep -q "^Model checking completed. No error has been found." "$out/$name.txt"; then
    got=pass
  elif v=$(grep -oE "^Error: Invariant [A-Za-z]+ is violated" "$out/$name.txt"); then
    got=$(awk '{print $3}' <<<"$v")
  elif v=$(grep -oE "^Error: Action property [A-Za-z]+" "$out/$name.txt"); then
    got=$(awk '{print $4}' <<<"$v")
  elif grep -q "^Error: Deadlock reached" "$out/$name.txt"; then
    got=stuck   # no step enabled and not every process finished: a modeling error
  else
    got=error
  fi
  local states
  states=$(grep -oE "[0-9,]+ distinct states found" "$out/$name.txt" | tail -1 | cut -d' ' -f1)
  if [[ $got == "$expect" ]]; then
    printf "ok    %-24s %-26s %s distinct states\n" "$name" "$got" "${states:-?}"
    return 0
  fi
  printf "FAIL  %-24s expected %s, got %s (see %s)\n" "$name" "$expect" "$got" "out/$name.txt"
  return 1
}

failed=0
start=$(date +%s)
while read -r name module variant attempts procs wake kind rest; do
  [[ -z $name ]] && continue
  if [[ $# -gt 0 ]] && ! printf '%s\n' "$@" | grep -qx "$name"; then continue; fi
  read -ra words <<<"$rest"
  expect=${words[-1]}
  unset 'words[-1]'
  run_check "$name" "$module" "$variant" "$attempts" "$procs" "$wake" "$kind" "$expect" "${words[@]}" || failed=1
  if [[ $# -gt 0 ]]; then
    grep -E "^Error|^State [0-9]+|^/\\\\ last|^/\\\\ pc" "$out/$name.txt" || true
  fi
done <<<"$CHECKS"
echo "$(( $(date +%s) - start ))s, outputs in verify/tla/out/"
exit $failed
