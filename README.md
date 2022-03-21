# OPAQUE
[![OPAQUE](https://github.com/bytemare/opaque/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/opaque/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)
[![codecov](https://codecov.io/gh/bytemare/opaque/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/opaque)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbytemare%2Fopaque.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbytemare%2Fopaque?ref=badge_shield)

This package implements [OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque), an asymmetric password-authenticated
key exchange protocol that is secure against pre-computation attacks. It enables a client to authenticate to a server
without ever revealing its password to the server. 

This implementation is developed by one of the authors of the RFC [Internet Draft](https://github.com/cfrg/draft-irtf-cfrg-opaque).
The main branch is in sync with the latest developments of the draft, and [the releases](https://github.com/bytemare/opaque/releases)
correspond to the [official draft versions](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque).

#### What is OPAQUE?

> OPAQUE is a PKI-free secure aPAKE that is secure against pre-computation attacks. OPAQUE provides forward secrecy with
> respect to password leakage while also hiding the password from the server, even during password registration. OPAQUE
> allows applications to increase the difficulty of offline dictionary attacks via iterated hashing or other key
> stretching schemes. OPAQUE is also extensible, allowing clients to safely store and retrieve arbitrary application data
> on servers using only their password.

#### References
- [The original paper](https://eprint.iacr.org/2018/163.pdf) from Jarecki, Krawczyk, and Xu.
- [OPAQUE is used in WhatsApp](https://engineering.fb.com/2021/09/10/security/whatsapp-e2ee-backups) to enable end-to-end encrypted backups.
- [The GitHub repo](https://github.com/cfrg/draft-irtf-cfrg-opaque) where the draft is being specified.

## Installation

```
  go get github.com/bytemare/opaque@latest
```

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/opaque) and [the project wiki](https://github.com/bytemare/opaque/wiki) . 

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/opaque/tags).

Minor v0.x versions match the corresponding CFRG draft version, the master branch implements the latest changes of [the draft development](https://github.com/cfrg/draft-irtf-cfrg-opaque).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
