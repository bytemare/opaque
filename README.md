# OPAQUE
[![OPAQUE](https://github.com/bytemare/opaque/actions/workflows/wf-analysis.yaml/badge.svg)](https://github.com/bytemare/opaque/actions/workflows/wf-analysis.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)
[![codecov](https://codecov.io/gh/bytemare/opaque/branch/main/graph/badge.svg?token=5bQfB0OctA)](https://codecov.io/gh/bytemare/opaque)

```
  import "github.com/bytemare/opaque"
```

This package implements [OPAQUE (RFC 9807)](https://datatracker.ietf.org/doc/rfc9807), the augmented password-authenticated key exchange (aPAKE) protocol,
that is secure against pre-computation attacks. It enables a client to authenticate to a server without ever revealing its
password to the server. 

This implementation is developed by one of the authors of the [RFC](https://datatracker.ietf.org/doc/rfc9807). It has not
been audited, and even though great care about security and performance has been taken, it comes with no warranty.

#### What is OPAQUE?

> OPAQUE is an aPAKE that is secure against pre-computation attacks. OPAQUE provides forward secrecy with
> respect to password leakage while also hiding the password from the server, even during password registration. OPAQUE
> allows applications to increase the difficulty of offline dictionary attacks via iterated hashing or other key
> stretching schemes. OPAQUE is also extensible, allowing clients to safely store and retrieve arbitrary application data
> on servers using only their password.

#### References
- [The original paper](https://eprint.iacr.org/2018/163.pdf) from Jarecki, Krawczyk, and Xu.
- [RFC 9807](https://datatracker.ietf.org/doc/rfc9807).
- [OPAQUE is used in WhatsApp](https://www.whatsapp.com/security/WhatsApp_Security_Encrypted_Backups_Whitepaper.pdf) to enable end-to-end encrypted backups.

## Documentation [![Go Reference](https://pkg.go.dev/badge/github.com/bytemare/opaque.svg)](https://pkg.go.dev/github.com/bytemare/opaque)

You can find the documentation and usage examples in [the package doc](https://pkg.go.dev/github.com/bytemare/opaque) and [the project wiki](https://github.com/bytemare/opaque/wiki) . 

[//]: # (
# TODO: provide a more detailed documentation in the README.md for quick start
    - short and concise minimal how-to to make it work, securely, and efficiently, and gotchas to avoid
    - list good aspects:
      - easy to use
      - server is stateless, therefore thread safe and can be used by multiple goroutines serving clients
      - secure defaults, no need to worry about configuring the protocol
      - highly configurable, but beware of the pitfalls, and use at your own risk
    - protocol overview and usage examples
    - mention that there's state
    - some indicators of good use
      - use the latest version of the protocol
      - secure defaults
      - don't send errors details back to the client, to avoid giving hints to an attacker
      - store and retrieve the server key material securely
      - verify KE3 before using the session key
      - the client can use the extra key to encrypt more stuff, that the server cannot decrypt
      - use the client session key to encrypt more stuff, that the server cannot decrypt
      - deport client OPRF key derivation to another service, such as a key management service, to avoid storing the global OPRF key on the same service that the rest of the protocol, though compromise of these keys does not immediately lead to account compromise.
      - since OPAQUE necessarily reveals the client identity to the server during regsitration and autehntication, it is recommended to use a secure channel to protect the client identity, such as TLS 1.3+
    - list pitfalls
      - rate limit and add user enumeration protections of top of the fake credentials mechanism
      - same configuration throughout the client lifecycle
        - same base config
        - same server key material and public key
      - client blinding is on the password: for the same password and same blind, the same element comes out. Users of this package
      may want to bind the session and provide a some context to the password, such as the username or email address, a session ID, or a nonce.
        - Maybe use or implement OPAQUE-TLS as described in Password-Authenticated TLS via OPAQUE and Post-Handshake Authentication at https://eprint.iacr.org/2023/220.pdf
        - Use exported authenticators TLS1.3 extension compatible with the standard library
    - client enumeration protection: how to define a unique credential_identifier on registration for non-existing clients? Because sending the same element will leak/lead to a client enumeration attack.
      - a credential_identifier must be unique for each client, from the moment is registers for the rest of the credential lifetime.
      - an idea could be to use a static value from the client provided during registration, such as the email address or username, and a globally shared random value, to create a unique credential_identifier. Upon registration request or login, the server uses the id and random value to derive the credential_identifier - avoiding to have to store it, and then uses it to derive the OPRF key and the server key material.
# todo: continue with the list or make it shorter?
# todo: make Wireshark packet Capture (PCAP) files available for the protocol, to help with debugging and understanding the protocol
)

## Versioning

[SemVer](https://semver.org) is used for versioning. For the versions available, see the [tags on the repository](https://github.com/bytemare/opaque/tags).

Minor v0.x versions match the corresponding CFRG draft version, the master branch implements the latest changes of [the draft development](https://github.com/cfrg/draft-irtf-cfrg-opaque).

## Contributing

Please read [CONTRIBUTING.md](.github/CONTRIBUTING.md) for details on the code of conduct, and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
