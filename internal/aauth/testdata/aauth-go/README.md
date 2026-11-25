# aauth-go wire vectors

`http-signature.json` is copied unchanged from
[aauth-dev/aauth-go](https://github.com/aauth-dev/aauth-go) at commit
`ae3796e3d77803aae5b542fb89aa96288d9c5190` (`testdata/vectors/`), under the
MIT license in `LICENSE`.

The vectors are language-neutral RFC 9421 request signatures under the AAuth
profile, produced by aauth-go's signer. ZeroID's verifier runs them as a
conformance check, so its signature base and checks agree with the reference
implementation without depending on it.
