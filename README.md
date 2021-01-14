# OPAQUE

OPAQUE implements the OPAQUE protocol allow for mutual public key client-server authentication, with the client only knowing a password, and the server knowing nothing about about the password.

This follows the latest commits and discussions in the ongoing draft: https://github.com/cfrg/draft-irtf-cfrg-opaque

!!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT. THERE ARE ABSOLUTELY NO WARRANTIES. !!!

This is active work in progress.

Implemented components:
- OPRF on groups Ristretto255, P-256, P-384, and P-512
- Authenticated key exchanges
    - 3DH
    - Sigma-I
    - ~~HMQV~~
- Random Key Robust envelope encryption: xor + hmac

Test vectors can be found in tests/allVectors.json.

Run example and tests
````
$ go test -v
````