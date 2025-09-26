// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

func TestErrorJoin_IsAndAs(t *testing.T) {
	// Compose a typical error chain from a high-level code with internal causes
	err := opaque.ErrKE2.Join(internal.ErrMissingMAC, internal.ErrSliceIsAllZeros)

	// Verify top-level code and internal causes are discoverable via errors.Is
	if !errors.Is(err, opaque.ErrKE2) {
		t.Fatal("expected errors.Is(err, ErrKE2) to be true")
	}
	if !errors.Is(err, internal.ErrMissingMAC) {
		t.Fatal("expected errors.Is(err, internal.ErrMissingMAC) to be true")
	}
	if !errors.Is(err, internal.ErrSliceIsAllZeros) {
		t.Fatal("expected errors.Is(err, internal.ErrSliceIsAllZeros) to be true")
	}

	// Verify errors.As can extract the ErrorCode and *Error
	var code opaque.ErrorCode
	if !errors.As(err, &code) {
		t.Fatal("expected errors.As(err, *ErrorCode) to succeed")
	}
	if !errors.Is(code, opaque.ErrCodeMessage) {
		t.Fatalf("expected code %v, got %v", opaque.ErrCodeMessage, code)
	}

	var oe *opaque.Error
	if !errors.As(err, &oe) {
		t.Fatal("expected errors.As(err, **Error) to succeed")
	}
	if !errors.Is(oe.Code, opaque.ErrCodeMessage) {
		t.Fatalf("expected *Error.Code %v, got %v", opaque.ErrCodeMessage, oe.Code)
	}
}

// Example: handling high-level errors and specific causes.
func Example_errorHandling() {
	// Simulate an error chain
	err := opaque.ErrAuthentication.Join(internal.ErrServerAuthentication, internal.ErrInvalidServerMac)

	switch {
	case errors.Is(err, opaque.ErrAuthentication):
		// top-level class
		fmt.Println("auth error: abort and do not use keys")
		// handle specific cause
		if errors.Is(err, internal.ErrInvalidServerMac) {
			fmt.Println("server MAC invalid: report generic failure")
		}
	case errors.Is(err, opaque.ErrRegistration):
		fmt.Println("registration error: notify client")
	default:
		fmt.Println("unexpected error")
	}
	// Output:
	// auth error: abort and do not use keys
	// server MAC invalid: report generic failure
}
