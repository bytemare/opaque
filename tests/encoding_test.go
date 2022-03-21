// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"testing"

	"github.com/bytemare/opaque/internal/encoding"
)

func TestEncodeVectorLenPanic(t *testing.T) {
	/*
		EncodeVectorLen with size > 2
	*/
	defer func() {
		recover()
	}()

	encoding.EncodeVectorLen(nil, 3)
	t.Fatal("no panic with exceeding encoding length")
}

func TestDecodeVector(t *testing.T) {
	/*
		DecodeVector with invalid header and payload
	*/

	badHeader := []byte{0}
	if _, _, err := encoding.DecodeVector(badHeader); err == nil ||
		err.Error() != "insufficient header length for decoding" {
		t.Fatalf("expected error for short input. Got %q", err)
	}

	badPayload := []byte{0, 3, 0, 0}
	if _, _, err := encoding.DecodeVector(badPayload); err == nil ||
		err.Error() != "insufficient total length for decoding" {
		t.Fatalf("expected error for short input. Got %q", err)
	}
}
