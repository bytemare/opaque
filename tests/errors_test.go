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
	"strings"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

// TestErrorJoin_IsAndAs confirms joined high-level errors preserve discoverability of both protocol codes and root causes so applications can react safely.
func TestErrorJoin_IsAndAs(t *testing.T) {
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

type opaqueErrorWrapper struct {
	err *opaque.Error
}

func (w opaqueErrorWrapper) Error() string { return w.err.Error() }

func (w opaqueErrorWrapper) As(target any) bool {
	switch t := target.(type) {
	case **opaque.Error:
		*t = w.err
		return true
	default:
		return false
	}
}

// TestErrorCodeIsOpaqueError demonstrates that ErrorCode.Is recognizes wrapped *opaque.Error values, ensuring the convenience helpers integrate cleanly with Go's errors APIs.
func TestErrorCodeIsOpaqueError(t *testing.T) {
	t.Parallel()

	target := opaqueErrorWrapper{err: opaque.ErrCodeRegistration.New("wrapped")}
	if !opaque.ErrCodeRegistration.Is(target) {
		t.Fatal("expected ErrorCode.Is to match *opaque.Error")
	}
	if opaque.ErrCodeRegistration.Is(opaque.ErrCodeAuthentication) {
		t.Fatal("expected different codes not to match")
	}
}

type nilUnwrapper struct{}

func (nilUnwrapper) Error() string { return "nil unwrap" }
func (nilUnwrapper) Unwrap() error { return nil }

// TestErrorFormatHandlesNilUnwrap verifies the verbose formatter tolerates custom error types whose Unwrap returns nil so logging never panics when exotic wrappers are encountered.
func TestErrorFormatHandlesNilUnwrap(t *testing.T) {
	t.Parallel()

	err := &opaque.Error{
		Code:    opaque.ErrCodeAuthentication,
		Message: "auth failed",
		Err:     nilUnwrapper{},
	}

	formatted := fmt.Sprintf("%+v", err)
	if !strings.Contains(formatted, "auth failed") {
		t.Fatalf("expected formatted error to include message, got %q", formatted)
	}
}
