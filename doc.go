// Package opaque implements the OPAQUE asymmetric password-authenticated key exchange protocol.
//
// OPAQUE is an asymmetric Password Authenticated Key Exchange (PAKE).
//
package opaque

/*
This package implements the OPAQUE password-authenticated key exchange protocol: it enables a server to authenticate
a client without ever learning the password, with strong security guarantees.

IT solves very recurrent problems of password management by servers, including plaintext storage or log leaks. Better,
OPAQUE also authenticates the server on client login without the need to trust a traditional PKI. On successful login,
both client and server share a secret session key that can be used for various purposes.
You can learn more about the protocol on the CFRG project page.

Minor versions of this package match the CFRG draft version, master implements the latest changes of the project.

```Go
  import "github.com/bytemare/opaque"
```

## The OPAQUE protocol

OPAQUE covers credential Registration (where a client record is created) and Login (mutual authentication) phases.
Both phases incorporate a client-enumeration mitigation that, if employed, needs the Registration phase to be done
over a confidential and authenticated channel. Both phases use 3 messages to complete.

The client only needs a password, and the server will store a so-called _verifier_ that contains a public key.

On Registration, the protocol allows the client to derive an `export_key` secret key it can use to encrypt

### Registration


### Login


## Security

### Supported Ciphersuites and Parameters

### Client Enumeration Protection

Version 0.6.0 implements the masked response, but does not

*/