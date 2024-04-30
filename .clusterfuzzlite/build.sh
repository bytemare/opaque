#!/bin/bash -eu

set -ex

# compile_go_fuzzer github.com/bytemare/opaque FuzzConfiguration Fuzz_Configuration fuzz
# compile_go_fuzzer github.com/bytemare/opaque FuzzDeserializeRegistrationRequest Fuzz_DeserializeRegistrationRequest fuzz
# compile_go_fuzzer github.com/bytemare/opaque FuzzDeserializeRegistrationResponse Fuzz_DeserializeRegistrationResponse fuzz
# compile_go_fuzzer github.com/bytemare/opaque FuzzDeserializeRegistrationRecord Fuzz_DeserializeRegistrationRecord fuzz
# compile_go_fuzzer github.com/bytemare/opaque FuzzDeserializeKE1 Fuzz_DeserializeKE1 fuzz
# compile_go_fuzzer github.com/bytemare/opaque FuzzDeserializeKE2 Fuzz_DeserializeKE2 fuzz
# compile_go_fuzzer github.com/bytemare/opaque FuzzDeserializeKE3 Fuzz_DeserializeKE3 fuzz
compile_go_fuzzer github.com/bytemare/opaque FuzzKE3 Fuzz_DeserializeKE3 fuzz
