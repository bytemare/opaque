#!/bin/bash -eu

compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzConfiguration Fuzz_Configuration fuzz
compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzDeserializeRegistrationRequest Fuzz_DeserializeRegistrationRequest fuzz
compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzDeserializeRegistrationResponse Fuzz_DeserializeRegistrationResponse fuzz
compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzDeserializeRegistrationRecord Fuzz_DeserializeRegistrationRecord fuzz
compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzDeserializeKE1 Fuzz_DeserializeKE1 fuzz
compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzDeserializeKE2 Fuzz_DeserializeKE2 fuzz
compile_go_fuzzer github.com/bytemare/opaque/test/opaque_test FuzzDeserializeKE3 Fuzz_DeserializeKE3 fuzz
