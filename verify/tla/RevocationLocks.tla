--------------------------- MODULE RevocationLocks ---------------------------
(***************************************************************************)
(* The row-lock protocol between delegated-token issuance and cascade      *)
(* revocation in ZeroID, as PostgreSQL runs it under READ COMMITTED.       *)
(*                                                                         *)
(* README.md maps every action below to the code (file:line) and lists    *)
(* the bounds, the assumptions and what is left out.                       *)
(*                                                                         *)
(* One action is one indivisible database step: a statement, or the       *)
(* acquisition of one row lock inside a statement that locks rows in a     *)
(* stated order.                                                           *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, Sequences

CONSTANTS
    Variant,        \* which version of the code; see Variants
    Attempts,       \* CascadeRevocationAttempts in internal/store/postgres/credential.go
    MaxProcs,       \* at most this many processes run in one behavior
    Tok,            \* every row: present at start, or stored by an issuance
    NoTok,          \* parent_jti of a token with no parent
    Parent,         \* [Tok -> Tok \cup {NoTok}]       parent_jti
    Ident,          \* [Tok -> identities]             identity_id
    OwnerOf,        \* [identities -> owners]          identities.owner_user_id
    Depth,          \* [Tok -> Nat]                    delegation_depth
    StartIssuedAt,  \* [Tok -> Nat]                    issued_at of rows present at start
    Ord,            \* [Tok -> Nat], injective         stands in for id (a UUID) in the sort
    Stored0,        \* rows present at start
    Revoked0,       \* rows already revoked at start
    Procs,          \* process names
    Kind,           \* [Procs -> {"issue", "single", "ident", "owner"}]
    Target,         \* issue: the row it stores; single: the token revoked (RFC 7009);
                    \* ident: the identity; owner: the owner user
    Clock,          \* [Procs -> SUBSET Nat]  time.Now() readings an issuance can take
    BackoffOutlastsWakeup \* TRUE: a retried cascade starts again only after every waiter
                    \* its rollback woke has taken its lock (runCascade sleeps 25 ms or more)

\* head         d43098e: 073/074 lock anchors and every live reached row in one ordered pass,
\*                       then walk again on a new snapshot and revoke.
\* round3       455764f: statement 1 locks the anchors only; statement 2 walks, locks the
\*                       reached rows in order (the `locked` CTE) and revokes.
\* round2       e5cb06f: statement 1 locks the anchors only; statement 2 walks and the UPDATE
\*                       locks the reached rows in plan order.
\* main         origin/main: one statement walks and the UPDATE locks in plan order; issuance
\*                       checks its parent without a lock and inserts.
\* no_recheck   head, but issuance does not refuse when the locked chain is revoked.
\* one_snapshot head, but statement 2 walks on statement 1's snapshot.
Variants == {"head", "round3", "round2", "main", "no_recheck", "one_snapshot"}
HeadLike == {"head", "no_recheck", "one_snapshot"}

ASSUME Variant \in Variants
ASSUME Attempts \in Nat \ {0}

VARIABLES
    stored,         \* committed rows: what a new snapshot sees
    revoked,        \* committed rows with is_revoked = TRUE
    issuedAt,       \* [Tok -> Nat] issued_at; for a row not yet stored, the issuance's clock
    lk,             \* [Tok -> [Procs -> {"none", "share", "nku"}]] row locks held
    pc,             \* [Procs -> label]
    todo,           \* [Procs -> Seq(Tok)] rows the current statement still has to lock, in order
    got,            \* [Procs -> SUBSET Tok] rows statement 2 locked that pass its WHERE
    chainRevoked,   \* [Procs -> BOOLEAN] issuance: a row it locked FOR SHARE was revoked
    snap1,          \* [Procs -> [st, rv]] statement 1's snapshot (one_snapshot only)
    attempt,        \* [Procs -> Nat] cascade attempt, 1..Attempts
    badIssue,       \* ghost: an issuance committed a row with a revoked ancestor
    last            \* ghost: the last step, in the code's words (excluded from VIEW)

vars == <<stored, revoked, issuedAt, lk, pc, todo, got, chainRevoked, snap1,
          attempt, badIssue, last>>
view == <<stored, revoked, issuedAt, lk, pc, todo, got, chainRevoked, snap1,
          attempt, badIssue>>

Cascades == {p \in Procs : Kind[p] \in {"single", "ident", "owner"}}
Issuers  == {p \in Procs : Kind[p] = "issue"}
Final    == {"absent", "done", "refused", "aborted", "committed", "failed"}

-----------------------------------------------------------------------------
(* Tree helpers. parent_jti never changes, so these read the constant.     *)

RECURSIVE Anc(_)
\* Every token above t.
Anc(t) == IF Parent[t] = NoTok THEN {} ELSE {Parent[t]} \cup Anc(Parent[t])

RECURSIVE RootFirst(_)
\* t and every token above it, the root first: lockLineageSQL's ORDER BY lineage.depth DESC.
RootFirst(t) == IF Parent[t] = NoTok THEN <<t>> ELSE RootFirst(Parent[t]) \o <<t>>

RECURSIVE Walk(_, _)
\* The recursive `chain` CTE: the anchors and every row below them that the snapshot st
\* holds. It walks through revoked rows (031); is_revoked is filtered after the walk.
Walk(S, st) == LET next == S \cup {t \in st : Parent[t] \in S}
               IN IF next = S THEN S ELSE Walk(next, st)

\* ORDER BY delegation_depth, issued_at, id
Before(a, b) ==
    \/ Depth[a] < Depth[b]
    \/ Depth[a] = Depth[b] /\ issuedAt[a] < issuedAt[b]
    \/ Depth[a] = Depth[b] /\ issuedAt[a] = issuedAt[b] /\ Ord[a] < Ord[b]

RECURSIVE Sorted(_)
Sorted(S) == IF S = {} THEN <<>>
             ELSE LET m == CHOOSE x \in S : \A y \in S \ {x} : Before(x, y)
                  IN <<m>> \o Sorted(S \ {m})

RECURSIVE Orders(_)
\* Every order a plan could visit S in (an UPDATE with no ORDER BY).
Orders(S) == IF S = {} THEN {<<>>}
             ELSE UNION {{<<x>> \o s : s \in Orders(S \ {x})} : x \in S}

\* The rows a cascade starts from, in the snapshot st.
Anchors(p, st) ==
    CASE Kind[p] = "single" -> {Target[p]} \cap st
      [] Kind[p] = "ident"  -> {t \in st : Ident[t] = Target[p]}
      [] Kind[p] = "owner"  -> {t \in st : OwnerOf[Ident[t]] = Target[p]}

\* The rows statement 1 locks, from the snapshot (st, rv).
Stmt1Rows(p, st, rv) ==
    IF Variant \in HeadLike
    THEN \* 073:72-92 and 074:74-93, 160-184: anchors plus every live reached row;
         \* 073 also locks its anchor when it is revoked.
         LET live == Walk(Anchors(p, st), st) \ rv
         IN IF Kind[p] = "single" THEN live \cup ({Target[p]} \cap st) ELSE live
    ELSE \* round2 / round3: the anchors only (unrevoked ones, for the bulk cascades).
         IF Kind[p] = "single" THEN {Target[p]} \cap st ELSE Anchors(p, st) \ rv

\* The rows the walk that revokes reaches and would revoke, from the snapshot (st, rv).
RevokeRows(p, st, rv) == Walk(Anchors(p, st), st) \ rv

-----------------------------------------------------------------------------
(* Row locks. FOR SHARE ("share") and FOR NO KEY UPDATE ("nku", which an   *)
(* UPDATE also takes) conflict; two FOR SHAREs do not; a transaction never *)
(* conflicts with itself.                                                  *)

Mode(p) == IF Kind[p] = "issue" THEN "share" ELSE "nku"
Conflicts(want, have) == IF want = "nku" THEN have # "none" ELSE have = "nku"
Free(p, r) == \A q \in Procs \ {p} : ~Conflicts(Mode(p), lk[r][q])
Release(p) == [r \in Tok |-> [lk[r] EXCEPT ![p] = "none"]]
Grant(p, r) == [lk EXCEPT ![r][p] = IF Mode(p) = "nku" THEN "nku"
                                    ELSE IF lk[r][p] = "nku" THEN "nku" ELSE "share"]

Locking == {"lineage", "s1", "s2"}

\* p is blocked on the next row it must lock, and q holds that row in a conflicting mode.
WaitsFor(p, q) ==
    /\ p # q
    /\ pc[p] \in Locking
    /\ todo[p] # <<>>
    /\ Conflicts(Mode(p), lk[Head(todo[p])][q])

RECURSIVE ReachW(_, _)
ReachW(S, n) == IF n = 0 THEN S
                ELSE ReachW(S \cup {q \in Procs : \E m \in S : WaitsFor(m, q)}, n - 1)
InCycle(p) == p \in ReachW({q \in Procs : WaitsFor(p, q)}, Cardinality(Procs))

-----------------------------------------------------------------------------
Init ==
    /\ \E S \in SUBSET Procs :
          /\ Cardinality(S) \in 2..MaxProcs
          /\ pc = [p \in Procs |-> IF p \in S THEN "start" ELSE "absent"]
    /\ stored = Stored0
    /\ revoked = Revoked0
    /\ issuedAt = StartIssuedAt
    /\ lk = [r \in Tok |-> [p \in Procs |-> "none"]]
    /\ todo = [p \in Procs |-> <<>>]
    /\ got = [p \in Procs |-> {}]
    /\ chainRevoked = [p \in Procs |-> FALSE]
    /\ snap1 = [p \in Procs |-> [st |-> {}, rv |-> {}]]
    /\ attempt = [p \in Procs |-> 1]
    /\ badIssue = FALSE
    /\ last = "init"

-----------------------------------------------------------------------------
(* Issuance of a delegated token (IssueCredential -> repo.Create).        *)

\* checkLineageUsable (service/credential.go:160): an unlocked read of the parent's chain.
\* main reads only the subject token's own row (IntrospectToken in the exchange).
\* The issuance also reads time.Now() here (service/credential.go:1048, 1354).
IssueCheck(p) ==
    LET c == Target[p]  par == Parent[c]
        seen == IF Variant = "main" THEN {par} ELSE {par} \cup Anc(par)
    IN
    /\ Kind[p] = "issue" /\ pc[p] = "start"
    /\ IF par # NoTok /\ (par \notin stored \/ seen \cap revoked # {})
       THEN \* an unknown or revoked subject_token: invalid_grant
            /\ pc' = [pc EXCEPT ![p] = "refused"]
            /\ last' = <<p, "lineage check: subject unknown or chain revoked, refused">>
            /\ UNCHANGED <<issuedAt, todo>>
       ELSE \E now \in Clock[p] :
            /\ issuedAt' = [issuedAt EXCEPT ![c] = now]
            /\ IF par = NoTok \/ Variant = "main"
               THEN /\ pc' = [pc EXCEPT ![p] = "insert"]
                    /\ UNCHANGED todo
               ELSE /\ pc' = [pc EXCEPT ![p] = "lineage"]
                    /\ todo' = [todo EXCEPT ![p] = RootFirst(par)]
            /\ last' = <<p, "lineage check passed">>
    /\ UNCHANGED <<stored, revoked, lk, got, chainRevoked, snap1, attempt, badIssue>>

\* lockLineageSQL (store/postgres/credential.go:83): one FOR SHARE row lock, root first.
\* A row updated by a transaction that committed while this one waited is returned as
\* it now is, so is_revoked is the committed value.
IssueLockRow(p) ==
    LET r == Head(todo[p]) IN
    /\ Kind[p] = "issue" /\ pc[p] = "lineage" /\ todo[p] # <<>>
    /\ Free(p, r)
    /\ lk' = Grant(p, r)
    /\ todo' = [todo EXCEPT ![p] = Tail(todo[p])]
    /\ chainRevoked' = [chainRevoked EXCEPT ![p] = chainRevoked[p] \/ r \in revoked]
    /\ last' = <<p, "FOR SHARE", r>>
    /\ UNCHANGED <<stored, revoked, issuedAt, pc, got, snap1, attempt, badIssue>>

\* Committing a stored row, and the checks a row with a revoked ancestor would fail.
StoreRow(p, c, at) ==
    /\ stored' = stored \cup {c}
    /\ issuedAt' = [issuedAt EXCEPT ![c] = at]
    /\ badIssue' = (badIssue \/ Anc(c) \cap revoked # {})

\* lockUnrevokedLineage's check (credential.go:120-130), the INSERT (credential.go:60)
\* and COMMIT (RunInTx, credential.go:71). The INSERT and the COMMIT are one step: the
\* row is invisible to every other snapshot until COMMIT and the INSERT takes no lock
\* anyone else waits on, so no other process can tell them apart.
IssueFinish(p) ==
    LET c == Target[p]  pa == issuedAt[Parent[c]]  own == issuedAt[c]
        at == IF own < pa + 1 THEN pa + 1 ELSE own     \* credential.go:56-58
    IN
    /\ Kind[p] = "issue" /\ pc[p] = "lineage" /\ todo[p] = <<>>
    /\ lk' = Release(p)
    /\ IF chainRevoked[p] /\ Variant # "no_recheck"
       THEN /\ pc' = [pc EXCEPT ![p] = "refused"]
            /\ last' = <<p, "ErrRevokedLineage, ROLLBACK">>
            /\ UNCHANGED <<stored, issuedAt, badIssue>>
       ELSE /\ StoreRow(p, c, at)
            /\ pc' = [pc EXCEPT ![p] = "done"]
            /\ last' = <<p, "INSERT and COMMIT", c>>
    /\ UNCHANGED <<revoked, todo, got, chainRevoked, snap1, attempt>>

\* A token with no parent (Create's plain INSERT, credential.go:66), or any issuance on
\* main (no lock at all): one autocommit INSERT.
IssueInsert(p) ==
    LET c == Target[p] IN
    /\ Kind[p] = "issue" /\ pc[p] = "insert"
    /\ StoreRow(p, c, issuedAt[c])
    /\ pc' = [pc EXCEPT ![p] = "done"]
    /\ last' = <<p, "INSERT (autocommit)", c>>
    /\ UNCHANGED <<revoked, lk, todo, got, chainRevoked, snap1, attempt>>

-----------------------------------------------------------------------------
(* Cascade revocation (runCascade -> one call of a plpgsql function).      *)

\* A process whose next row is free, such as a waiter a rollback just woke.
Woken(q) == pc[q] \in Locking /\ todo[q] # <<>> /\ Free(q, Head(todo[q]))

\* Statement 1 starts: its snapshot is taken, the walk runs on it, and the rows to lock
\* are sorted. On main the only statement is the walk-and-UPDATE, so it goes to "s2".
\* A retried cascade first sleeps in runCascade (credential.go:292); with
\* BackoffOutlastsWakeup it starts again only once no other process has a lock step
\* it can take.

CascadeStart(p) ==
    /\ p \in Cascades /\ pc[p] = "start"
    /\ (BackoffOutlastsWakeup /\ attempt[p] > 1) => \A q \in Procs \ {p} : ~Woken(q)
    /\ got' = [got EXCEPT ![p] = {}]
    /\ IF Variant = "main"
       THEN \E s \in Orders(RevokeRows(p, stored, revoked)) :
               /\ todo' = [todo EXCEPT ![p] = s]
               /\ pc' = [pc EXCEPT ![p] = "s2"]
               /\ UNCHANGED snap1
       ELSE /\ todo' = [todo EXCEPT ![p] = Sorted(Stmt1Rows(p, stored, revoked))]
            /\ pc' = [pc EXCEPT ![p] = "s1"]
            /\ snap1' = IF Variant = "one_snapshot"
                        THEN [snap1 EXCEPT ![p] = [st |-> stored, rv |-> revoked]]
                        ELSE snap1
    /\ last' = <<p, IF Variant = "main" THEN "walk-and-UPDATE statement starts"
                     ELSE "statement 1 starts", attempt[p]>>
    /\ UNCHANGED <<stored, revoked, issuedAt, lk, chainRevoked, attempt, badIssue>>

\* One FOR NO KEY UPDATE row lock (statement 1's PERFORM, statement 2's `locked` CTE, or
\* the UPDATE itself). After a wait the row's latest version is rechecked against the
\* WHERE (is_revoked = FALSE); only statement 2's result is used.
CascadeLockRow(p) ==
    LET r == Head(todo[p]) IN
    /\ p \in Cascades /\ pc[p] \in {"s1", "s2"} /\ todo[p] # <<>>
    /\ Free(p, r)
    /\ lk' = Grant(p, r)
    /\ todo' = [todo EXCEPT ![p] = Tail(todo[p])]
    /\ got' = IF pc[p] = "s2" /\ r \notin revoked
              THEN [got EXCEPT ![p] = got[p] \cup {r}] ELSE got
    /\ last' = <<p, IF pc[p] = "s1" THEN "statement 1 locks" ELSE "statement 2 locks", r>>
    /\ UNCHANGED <<stored, revoked, issuedAt, pc, chainRevoked, snap1, attempt, badIssue>>

\* Statement 2 starts on a new snapshot (a later statement of a VOLATILE plpgsql function
\* under READ COMMITTED) and walks again. one_snapshot reuses statement 1's.
CascadeStmt2(p) ==
    LET st == IF Variant = "one_snapshot" THEN snap1[p].st ELSE stored
        rv == IF Variant = "one_snapshot" THEN snap1[p].rv ELSE revoked
        rows == RevokeRows(p, st, rv)
    IN
    /\ p \in Cascades /\ pc[p] = "s1" /\ todo[p] = <<>>
    /\ IF Variant = "round2"
       THEN \E s \in Orders(rows) : todo' = [todo EXCEPT ![p] = s]
       ELSE todo' = [todo EXCEPT ![p] = Sorted(rows)]
    /\ pc' = [pc EXCEPT ![p] = "s2"]
    /\ last' = <<p, "statement 2 starts">>
    /\ UNCHANGED <<stored, revoked, issuedAt, lk, got, chainRevoked, snap1, attempt, badIssue>>

\* The UPDATE of the rows statement 2 locked, and COMMIT (the function call is one
\* autocommit statement). One step: every row it writes is already locked by it and
\* its writes are invisible until COMMIT.
CascadeCommit(p) ==
    /\ p \in Cascades /\ pc[p] = "s2" /\ todo[p] = <<>>
    /\ revoked' = revoked \cup got[p]
    /\ lk' = Release(p)
    /\ pc' = [pc EXCEPT ![p] = "committed"]
    /\ last' = <<p, "UPDATE and COMMIT", got[p]>>
    /\ UNCHANGED <<stored, issuedAt, todo, got, chainRevoked, snap1, attempt, badIssue>>

-----------------------------------------------------------------------------
\* PostgreSQL's deadlock detector aborts one transaction on a wait cycle (40P01). A
\* cascade outside a caller's transaction is run again by runCascade
\* (credential.go:273-297) until it has run Attempts times; an issuance is not.
DeadlockAbort(p) ==
    /\ InCycle(p)
    /\ lk' = Release(p)
    /\ todo' = [todo EXCEPT ![p] = <<>>]
    /\ got' = [got EXCEPT ![p] = {}]
    /\ chainRevoked' = [chainRevoked EXCEPT ![p] = FALSE]
    /\ IF p \in Issuers
       THEN /\ pc' = [pc EXCEPT ![p] = "aborted"]
            /\ UNCHANGED attempt
       ELSE IF attempt[p] < Attempts
            THEN /\ pc' = [pc EXCEPT ![p] = "start"]
                 /\ attempt' = [attempt EXCEPT ![p] = attempt[p] + 1]
            ELSE /\ pc' = [pc EXCEPT ![p] = "failed"]
                 /\ UNCHANGED attempt
    /\ last' = <<p, "40P01 deadlock victim, rolled back">>
    /\ UNCHANGED <<stored, revoked, issuedAt, snap1, badIssue>>

Done == /\ \A p \in Procs : pc[p] \in Final
        /\ UNCHANGED vars

Step(p) ==
    \/ IssueCheck(p) \/ IssueLockRow(p) \/ IssueFinish(p) \/ IssueInsert(p)
    \/ CascadeStart(p) \/ CascadeLockRow(p) \/ CascadeStmt2(p) \/ CascadeCommit(p)
    \/ DeadlockAbort(p)

Next == (\E p \in Procs : Step(p)) \/ Done

Spec == Init /\ [][Next]_vars
FairSpec == Spec /\ WF_vars(Next)

-----------------------------------------------------------------------------
(* Properties.                                                             *)

TypeOK ==
    /\ stored \subseteq Tok /\ revoked \subseteq stored
    /\ \A r \in Tok : \A p \in Procs : lk[r][p] \in {"none", "share", "nku"}
    /\ \A r \in Tok : Cardinality({p \in Procs : lk[r][p] = "nku"}) <= 1
    /\ \A r \in Tok : (\E p \in Procs : lk[r][p] = "nku") =>
                         \A q \in Procs : lk[r][q] # "share"
    /\ \A p \in Procs : attempt[p] \in 1..Attempts

\* Safety 1: no live token has a revoked ancestor (rlLiveBelowRevokedSQL in
\* tests/integration/revoked_lineage_helpers_test.go is the same query).
NoLiveTokenBelowRevoked ==
    \A t \in stored \ revoked : Anc(t) \cap revoked = {}

\* Safety 2: no issuance commits a token below a token whose revocation has committed.
NoIssuanceBelowRevoked == ~badIssue

\* No reachable state where processes wait on each other in a cycle.
NoDeadlock == \A p \in Procs : ~InCycle(p)

\* Liveness. FairSpec's behaviors are finite: every step other than Done lowers
\* Measure (Progress below), so under WF_vars(Next) each behavior reaches a state
\* where only Done can stutter, and Done is enabled only when every process has
\* finished. So, for this model:
\*   AllFinish              <=> TLC finds no "deadlock" (a state with no step enabled)
\*   EveryRevocationCommits <=> NoRevocationFails, since "committed", "failed" and
\*                              "absent" are a cascade's only final labels.
\* run.sh checks the right-hand sides. TLC's temporal checker re-evaluates the
\* scenario constants in every state and does not finish on these models.
AllFinish == <>(\A p \in Procs : pc[p] \in Final)
EveryRevocationCommits == \A p \in Cascades : <>(pc[p] \in {"absent", "committed"})

NoRevocationFails == \A p \in Cascades : pc[p] # "failed"

StepsLeft(p) ==
    CASE pc[p] = "start"                 -> 3
      [] pc[p] \in {"lineage", "s1"}     -> 2
      [] pc[p] \in {"insert", "s2"}      -> 1
      [] OTHER                           -> 0
Measure(p) == ((Attempts - attempt[p]) * 4 + StepsLeft(p)) * (Cardinality(Tok) + 1)
              + Len(todo[p])
RECURSIVE SumOver(_)
SumOver(S) == IF S = {} THEN 0
              ELSE LET p == CHOOSE x \in S : TRUE IN Measure(p) + SumOver(S \ {p})
Progress == [][Done \/ SumOver(Procs)' < SumOver(Procs)]_vars
=============================================================================
