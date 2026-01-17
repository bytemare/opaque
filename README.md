# OPAQUE

[![OPAQUE](https://github.com/bytemare/opaque/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/opaque/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)
[![codecov](https://codecov.io/gh/bytemare/opaque/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/opaque)

```go
  import "github.com/bytemare/opaque"
```

This package implements [OPAQUE (RFC 9807)](https://datatracker.ietf.org/doc/rfc9807),
the augmented password-authenticated key exchange (aPAKE) protocol that is
secure against pre-computation attacks. It enables a client to authenticate to
a server without ever revealing its password to the server.

This implementation is developed by one of the authors of the
[RFC](https://datatracker.ietf.org/doc/rfc9807). It has not been audited, and
even though great care about security and performance has been taken, it comes
with no warranty.

## What is OPAQUE?

> OPAQUE is an aPAKE that is secure against pre-computation attacks. OPAQUE
> provides forward secrecy with respect to password leakage while also hiding
> the password from the server, even during password registration. OPAQUE allows
> applications to increase the difficulty of offline dictionary attacks via
> iterated hashing or other key stretching schemes. OPAQUE is also extensible,
> allowing clients to safely store and retrieve arbitrary application data on
> servers using only their password.

## References

- [The original paper](https://eprint.iacr.org/2018/163.pdf) from Jarecki,
  Krawczyk, and Xu.
- [RFC 9807](https://datatracker.ietf.org/doc/rfc9807).
- [OPAQUE in WhatsApp](https://www.whatsapp.com/security/WhatsApp_Security_Encrypted_Backups_Whitepaper.pdf)
  to enable end-to-end encrypted backups.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/opaque).

## Security and Operational Notes

- Use a confidential transport (e.g., TLS 1.3+) to protect client identities on
  the wire.
- Keep the OPRF global seed single and stable across clients, and derive unique
  per-client OPRF keys using a stable, unique credential identifier.
- Ensure consistent configuration (groups, hashes, KSF) across registration and
  subsequent logins.
- The server must always verify KE3 with `LoginFinish` before using the session
  secret.
- For unknown users, return a fake record (`GetFakeRecord`) to reduce
  user-enumeration signals.
- Rate limiting and replay tracking are application responsibilities. OPAQUE
  authenticates transcripts; session management is up to you.
- The server is concurrency-safe for typical use. Avoid a hidden global state in
  your app layer.
- Store `ServerKeyMaterial` securely. Treat secrets (e.g., private key and OPRF
  seed) appropriately.
- `Client.ClearState()` best-effort clears ephemeral material, but zeroization
  has language/runtime limits.

## Versioning

[SemVer](https://semver.org) is used for versioning. For the versions
available, see the [tags on the repository](https://github.com/bytemare/opaque/tags).

Minor v0.x versions match the corresponding CFRG draft version; the master
branch implements the latest changes of [the draft development](https://github.com/cfrg/draft-irtf-cfrg-opaque).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code
of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE)
file for details.
