// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
)

// TestEncodeVectorLenPanic ensures the helper panics when asked to encode lengths beyond the supported width, guarding against silent truncation of variable-length fields.
func TestEncodeVectorLenPanic(t *testing.T) {
	/*
		EncodeVectorLen with size > 2
	*/
	defer func() {
		recover()
	}()

	encoding.EncodeVectorLen(nil, 5)
	t.Fatal("no panic with exceeding encoding length")
}

// TestDecodeVector checks the decoder rejects short headers and truncated payloads, preventing out-of-bounds reads in message parsing.
func TestDecodeVector(t *testing.T) {
	/*
		DecodeVector with invalid header and payload
	*/

	badHeader := []byte{0}
	expectErrors(t, func() error {
		_, _, err := encoding.DecodeVector(badHeader)
		return err
	}, encoding.ErrDecoding, encoding.ErrHeaderLength)

	badPayload := []byte{0, 3, 0, 0}
	expectErrors(t, func() error {
		_, _, err := encoding.DecodeVector(badPayload)
		return err
	}, encoding.ErrDecoding, encoding.ErrTotalLength)
}

type i2ospTest struct {
	encoded []byte
	value   int
	size    uint16
}

var I2OSPVectors = []i2ospTest{
	{
		[]byte{0}, 0, 1,
	},
	{
		[]byte{1}, 1, 1,
	},
	{
		[]byte{0x20}, 32, 1,
	},
	{
		[]byte{0xff}, 255, 1,
	},
	{
		[]byte{0x00, 0x20}, 32, 2,
	},
	{
		[]byte{0x01, 0x00}, 256, 2,
	},
	{
		[]byte{0xff, 0xff}, 65535, 2,
	},
	{
		[]byte{0x01, 0x00, 0x00}, 65536, 3,
	},
	{
		[]byte{0xff, 0xff, 0xff}, 16777215, 3,
	},
	{
		[]byte{0x01, 0x00, 0x00, 0x00}, 16777216, 4,
	},
	{
		[]byte{0xff, 0xff, 0xff, 0xff}, 4294967295, 4,
	},
}

/*
expectErrors(t, func() error {
			_, _, err = server.GenerateKE2(ke1, nil)
			return err
		}, internal.ErrServerKeyMaterialNil)
*/

// TestI2OSP covers known-good integer encodings and the reverse OS2IP path, ensuring canonical big-endian conversion for protocol constants.
func TestI2OSP(t *testing.T) {
	for i, v := range I2OSPVectors {
		t.Run(fmt.Sprintf("%d - %d - %v", v.value, v.size, v.encoded), func(t *testing.T) {
			r := encoding.I2OSP(v.value, v.size)

			if !bytes.Equal(r, v.encoded) {
				t.Fatalf(
					"invalid encoding for %d. Expected '%s', got '%v'",
					i,
					hex.EncodeToString(v.encoded),
					hex.EncodeToString(r),
				)
			}

			value := encoding.OS2IP(v.encoded)
			if v.value != value {
				t.Errorf("invalid decoding for %d. Expected %d, got %d", i, v.value, value)
			}
		})
	}

	lengths := map[int]uint16{
		100:           1,
		1 << 8:        2,
		1 << 16:       3,
		(1 << 32) - 1: 4,
	}

	for k, v := range lengths {
		r := encoding.I2OSP(k, v)

		if uint16(len(r)) != v {
			t.Fatalf("invalid length for %d. Expected '%d', got '%d' (%v)", k, v, len(r), r)
		}
	}
}

// TestI2OSP_Failures verifies the encoder panics on invalid inputs, so callers cannot accidentally produce truncated or negative encodings.
func TestI2OSP_Failures(t *testing.T) {
	tests := []struct {
		expectedError error
		name          string
		value         int
		length        uint16
	}{
		{
			name:          "0 length",
			value:         1,
			length:        0,
			expectedError: encoding.ErrLengthNegativeOrZero,
		},
		{
			name:          "length too big",
			value:         1,
			length:        5,
			expectedError: encoding.ErrLengthTooBig,
		},
		{
			name:          "negative input",
			value:         -1,
			length:        4,
			expectedError: encoding.ErrInputNegative,
		},
		{
			name:          "exceeding value for the length",
			value:         1 << 32,
			length:        1,
			expectedError: encoding.ErrInputLarge,
		},
	}

	for _, te := range tests {
		t.Run(fmt.Sprintf("%s", te.name), func(t *testing.T) {
			if hasPanic, err := expectPanic(te.expectedError, func() {
				_ = encoding.I2OSP(te.value, te.length)
			}); !hasPanic {
				t.Fatalf("expected panic with with 0 length: %v", err)
			}
		})
	}
}

// TestOS2IP_Failures confirms decoding out-of-range or empty byte slices results in panics with descriptive errors, making length validation explicit for upstream callers.
func TestOS2IP_Failures(t *testing.T) {
	tests := []struct {
		expectedError error
		name          string
		input         []byte
	}{
		{
			name:          "nil input",
			input:         nil,
			expectedError: encoding.ErrInputEmpty,
		},
		{
			name:          "empty input",
			input:         []byte{},
			expectedError: encoding.ErrInputEmpty,
		},
		{
			name:          "too long",
			input:         []byte{1, 2, 3, 4, 5},
			expectedError: encoding.ErrInputTooLarge,
		},
	}

	for _, te := range tests {
		t.Run(fmt.Sprintf("%s", te.name), func(t *testing.T) {
			if hasPanic, err := expectPanic(te.expectedError, func() {
				_ = encoding.OS2IP(te.input)
			}); !hasPanic {
				t.Fatalf("expected panic with with 0 length: %v", err)
			}
		})
	}
}

func hasPanic(f func()) (has bool, err error) {
	err = nil
	var report interface{}
	func() {
		defer func() {
			if report = recover(); report != nil {
				has = true
			}
		}()

		f()
	}()

	if has {
		err = fmt.Errorf("%v", report)
	}

	return has, err
}

func expectPanic(expectedError error, f func()) (bool, string) {
	hasPanic, err := hasPanic(f)

	if !hasPanic {
		return false, "no panic"
	}

	if expectedError == nil {
		return true, ""
	}

	if err == nil {
		return false, "panic but no message"
	}

	if err.Error() != expectedError.Error() {
		return false, fmt.Sprintf("expected %q, got %q", expectedError, err)
	}

	return true, ""
}

// TestDecodeLongVector exercises the long-vector decoder on a valid payload, guaranteeing structured server material can be decoded across vectors.
func TestDecodeLongVector(t *testing.T) {
	conf := opaque.DefaultConfiguration()
	g := conf.AKE.Group()
	id := internal.RandomBytes(10)
	sk := g.NewScalar().Random()
	pk := g.Base().Multiply(sk)

	encoded := encoding.Concatenate(
		encoding.EncodeVector(id),
		encoding.EncodeVector(sk.Encode()),
		encoding.EncodeVector(pk.Encode()),
	)

	var decodedID, decodedSK, decodedPK []byte
	if err := encoding.DecodeLongVector(encoded, &decodedID, &decodedSK, &decodedPK); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(id, decodedID) {
		t.Fatalf("invalid ID. Expected %s, got %s", hex.EncodeToString(id), hex.EncodeToString(decodedID))
	}

	dsk := g.NewScalar()
	if err := dsk.Decode(decodedSK); err != nil {
		t.Fatal(err)
	}

	if !dsk.Equal(sk) {
		t.Fatalf("invalid scalar. Expected %s, got %s", sk.Hex(), dsk.Hex())
	}

	dpk := g.NewElement()
	if err := dpk.Decode(decodedPK); err != nil {
		t.Fatal(err)
	}

	if !dpk.Equal(pk) {
		t.Fatalf("invalid element. Expected %s, got %s", pk.Hex(), dpk.Hex())
	}
}

// TestDecodeLongVector_TooShort enumerates malformed long-vector encodings so each error path is covered, ensuring edge cases surface useful diagnostics.
func TestDecodeLongVector_TooShort(t *testing.T) {
	type testType struct {
		name          string
		input         []byte
		output        []*[]byte
		expectedError []error
	}

	tests := []testType{
		{
			name:          "short input",
			input:         []byte{2},
			output:        nil,
			expectedError: []error{encoding.ErrDecoding, encoding.ErrHeaderLength},
		},
		{
			name:          "missing output vectors",
			input:         encoding.EncodeVector([]byte{1, 2, 3}),
			output:        nil,
			expectedError: []error{encoding.ErrDecoding, encoding.ErrMissingOutput},
		},
		{
			name:          "nil output vector",
			input:         encoding.EncodeVector([]byte{1, 2, 3}),
			output:        []*[]byte{{}, nil},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrNilOutput},
		},
		{
			name:          "nil output vector in slice",
			input:         encoding.EncodeVector([]byte{1, 2, 3}),
			output:        []*[]byte{nil},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrNilOutput},
		},
		{
			name:          "empty encoded slice",
			input:         []byte{},
			output:        []*[]byte{{}},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrHeaderLength},
		},
		{
			name:          "incomplete payload",
			input:         encoding.EncodeVector([]byte{1, 2, 3})[:3],
			output:        []*[]byte{{}},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrTotalLength},
		},
		{
			name:          "bad payload header",
			input:         []byte{0},
			output:        []*[]byte{{}},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrHeaderLength},
		},
		{
			name:          "bad payload length",
			input:         []byte{0, 3, 0},
			output:        []*[]byte{{}},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrTotalLength},
		},
		{
			name:          "empty payload",
			input:         []byte{0, 0},
			output:        []*[]byte{{}},
			expectedError: []error{encoding.ErrDecoding, encoding.ErrEmptyEncoded},
		},
	}

	for _, te := range tests {
		t.Run(te.name, func(t *testing.T) {
			expectErrors(t, func() error {
				return encoding.DecodeLongVector(te.input, te.output...)
			}, te.expectedError...)
		})
	}
}
