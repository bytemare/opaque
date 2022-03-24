// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
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

	"github.com/bytemare/opaque/internal/encoding"
)

type I2OSPTest struct {
	value   int
	size    int
	encoded []byte
}

var I2OSPVectors = []I2OSPTest{
	{
		0, 1, []byte{0},
	},
	{
		1, 1, []byte{1},
	},
	{
		255, 1, []byte{0xff},
	},
	{
		256, 2, []byte{0x01, 0x00},
	},
	{
		65535, 2, []byte{0xff, 0xff},
	},
	{
		16770000, 3, []byte{0xff, 0xe3, 0xd0},
	},
	{
		4294960000, 4, []byte{0xff, 0xff, 0xe3, 0x80},
	},
}

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

	length := -1
	if hasPanic, err := expectPanic(nil, func() {
		_ = encoding.I2OSP(1, length)
	}); !hasPanic {
		t.Fatalf("expected panic with with negative length: %v", err)
	}

	length = 0
	if hasPanic, err := expectPanic(nil, func() {
		_ = encoding.I2OSP(1, length)
	}); !hasPanic {
		t.Fatalf("expected panic with with 0 length: %v", err)
	}

	length = 5
	if hasPanic, err := expectPanic(nil, func() {
		_ = encoding.I2OSP(1, length)
	}); !hasPanic {
		t.Fatalf("expected panic with length too big: %v", err)
	}

	negative := -1
	if hasPanic, err := expectPanic(nil, func() {
		_ = encoding.I2OSP(negative, 4)
	}); !hasPanic {
		t.Fatalf("expected panic with negative input: %v", err)
	}

	tooLarge := 1 << 32
	length = 1
	if hasPanic, err := expectPanic(nil, func() {
		_ = encoding.I2OSP(tooLarge, length)
	}); !hasPanic {
		t.Fatalf("expected panic with exceeding value for the length: %v", err)
	}

	lengths := map[int]int{
		100:           1,
		1 << 8:        2,
		1 << 16:       3,
		(1 << 32) - 1: 4,
	}

	for k, v := range lengths {
		r := encoding.I2OSP(k, v)

		if len(r) != v {
			t.Fatalf("invalid length for %d. Expected '%d', got '%d' (%v)", k, v, len(r), r)
		}
	}
}

func TestOS2IP(t *testing.T) {
	// No input
	if hasPanic, _ := expectPanic(nil, func() {
		_ = encoding.OS2IP(nil)
	}); !hasPanic {
		t.Fatal("expected panic with nil input")
	}

	// Empty input
	if hasPanic, _ := expectPanic(nil, func() {
		_ = encoding.OS2IP([]byte(""))
	}); !hasPanic {
		t.Fatal("expected panic with empty input")
	}

	// Exceeding input
	input := "12345"
	if hasPanic, _ := expectPanic(nil, func() {
		_ = encoding.OS2IP([]byte(input))
	}); !hasPanic {
		t.Fatal("expected panic with big input")
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

	return
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
