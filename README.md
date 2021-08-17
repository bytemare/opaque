# OPAQUE
[![OPAQUE](https://github.com/bytemare/opaque/actions/workflows/ci.yml/badge.svg)](https://github.com/bytemare/opaque/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)
[![codecov](https://codecov.io/gh/bytemare/opaque/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/opaque)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbytemare%2Fopaque.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbytemare%2Fopaque?ref=badge_shield)

This package implements the asymmetric password-authenticated key exchange protocol as in the latest [Internet Draft](https://github.com/cfrg/draft-irtf-cfrg-opaque).

[OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque) enables a client to authenticate to a server without ever revealing its password, with strong security guarantees. The server and client share a nice session secret on successful authentication.

## Installation

```
  go get github.com/bytemare/opaque@v0.6.0
```

## Usage

You can find the documentation and usage examples in [the project wiki](https://github.com/bytemare/opaque/wiki) and [the package doc](https://pkg.go.dev/github.com/bytemare/opaque). 

## Versioning

[SemVer](http://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/opaque/tags).

Minor v0.x versions match the corresponding CFRG draft version, the master branch implements the latest changes of [the draft development](https://github.com/cfrg/draft-irtf-cfrg-opaque).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
