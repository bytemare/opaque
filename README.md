# OPAQUE

This package implements the OPAQUE protocol. It allows for password based mutual public key client-server authentication. Only the client ever knows the password.

It follows the latest commits and discussions in the ongoing draft: https://github.com/cfrg/draft-irtf-cfrg-opaque

!!! WARNING : THIS IMPLEMENTATION IS PROOF OF CONCEPT AND BASED ON THE LATEST INTERNET DRAFT. THERE ARE ABSOLUTELY NO WARRANTIES. !!!

This is active work in progress.

Test vectors can be found in the __tests__ directory.

Run example and tests
````
$ go test -v
````