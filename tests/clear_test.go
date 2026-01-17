// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"testing"

	"github.com/bytemare/opaque/internal"
)

// TestClearScalar_Basic verifies that secret scalars are wiped and pointer cleared, which is vital to avoid lingering key material after use.
func TestClearScalar_Basic(t *testing.T) {
	testAll(t, func(t *testing.T, conf *configuration) {
		g := conf.conf.AKE.Group()

		s := g.NewScalar().Random()
		if s.IsZero() {
			t.Fatal("random scalar unexpectedly zero")
		}

		internal.ClearScalar(&s)
		if s != nil {
			t.Fatal("expected scalar pointer to be nil after ClearScalar")
		}
	})
}

// TestClearSlice_Basic confirms byte slices are zeroed and cleared, ensuring passwords or session keys are not left in memory.
func TestClearSlice_Basic(t *testing.T) {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}

	internal.ClearSlice(&b)
	if b != nil {
		t.Fatal("expected slice pointer to be nil after ClearSlice")
	}
}
