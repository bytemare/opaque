#!/bin/bash -eu

compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzConfiguration fuzz_Configuration fuzz
compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzDeserializeRegistrationRequest fuzz_DeserializeRegistrationRequest fuzz
compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzDeserializeRegistrationResponse fuzz_DeserializeRegistrationResponse fuzz
compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzDeserializeRegistrationRecord fuzz_DeserializeRegistrationRecord fuzz
compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzDeserializeKE1 fuzz_DeserializeKE1 fuzz
compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzDeserializeKE2 fuzz_DeserializeKE2 fuzz
compile_native_go_fuzzer github.com/bytemare/opaque/test FuzzDeserializeKE3 fuzz_DeserializeKE3 fuzz
