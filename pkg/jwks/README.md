# pkg/jwks

A remote JWKS client: fetch, cache, background-refresh, and refresh-on-unknown-`kid`.

It exists as its own module because **both** sides of zeroid need it and neither
should depend on the other:

- `github.com/highflame-ai/zeroid` — the authorization server, which fetches
  external IdP key sets (federated token exchange) and client `jwks_uri` key sets
  (RFC 7523 `private_key_jwt`).
- `github.com/highflame-ai/zeroid/pkg/authjwt` — the verification library resource
  servers import to validate zeroid-issued tokens.

Before this split, zeroid imported `pkg/authjwt` to get this client. That put a
*token-verification library for resource servers* in the dependency graph of the
*authorization server* — backwards layering — and leaked `authjwt` types into
zeroid's own exported API. `pkg/authjwt` now re-exports this package's types as
aliases, so its consumers are unaffected.

Versioned in lockstep with zeroid; see `RELEASING.md`.

## Why not use `jwx`'s cache directly

`jwx` v4 dropped `jwk.Fetch` / `jwk.WithHTTPClient`, so there is no supported way
to supply a custom `*http.Client` — which zeroid requires, because every outbound
fetch must go through an SSRF-guarded client. This package does the GET itself and
feeds the body to `jwk.Parse`, keeping the dependency footprint flat.
