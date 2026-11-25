#!/bin/sh
# ZeroID's signing keys for the demo, generated once into the keys volume:
# ES256 and RS256 for OAuth tokens (as `make setup-keys`), and the Ed25519
# key that signs AAuth agent tokens and nothing else.
set -eu
cd /keys
[ -f aauth_ed25519.pem ] && exit 0
openssl ecparam -genkey -name prime256v1 -noout -out private.pem
openssl ec -in private.pem -pubout -out public.pem
openssl genrsa -out rsa_private.pem 2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
openssl genpkey -algorithm ed25519 -out aauth_ed25519.pem
chmod 644 *.pem
