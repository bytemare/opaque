# OPAQUE
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbytemare%2Fopaque.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbytemare%2Fopaque?ref=badge_shield)


OPAQUE implemens the OPAQUE protocol allow for mutual client-server authentication without the server knowing the client's secret.

This implements https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-06

!!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT. THERE ARE ABSOLUTELY NO WARRANTIES. !!!

This is active work in progress.

Implemented components:
- (V)OPRF
- Authenticated key exchanges
    - Sigma-I
- Random-key Robust Authenticated Encryption Encrypt-then-HMAC schemes (RKR AE)
    - AES-CTR-Encrypt_then_HMAC-SHA2-256

## License
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fbytemare%2Fopaque.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fbytemare%2Fopaque?ref=badge_large)