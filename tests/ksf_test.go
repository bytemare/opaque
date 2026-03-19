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

	"github.com/bytemare/ksf"

	internalKSF "github.com/bytemare/opaque/internal/ksf"
)

// TestKSFOptionsSet_InvalidParameterValues ensures invalid parameter values are rejected before any underlying KSF can panic.
func TestKSFOptionsSet_InvalidParameterValues(t *testing.T) {
	tests := []struct {
		name       string
		id         ksf.Identifier
		parameters []uint64
		expected   error
	}{
		{name: "argon2id-time-zero", id: ksf.Argon2id, parameters: []uint64{0, 65536, 4}, expected: internalKSF.ErrParameterValue},
		{name: "argon2id-memory-zero", id: ksf.Argon2id, parameters: []uint64{3, 0, 4}, expected: internalKSF.ErrParameterValue},
		{name: "argon2id-threads-zero", id: ksf.Argon2id, parameters: []uint64{3, 65536, 0}, expected: internalKSF.ErrParameterValue},
		{name: "argon2id-threads-too-large", id: ksf.Argon2id, parameters: []uint64{3, 65536, 256}, expected: internalKSF.ErrParameterValue},
		{name: "scrypt-n-too-small", id: ksf.Scrypt, parameters: []uint64{1, 8, 1}, expected: internalKSF.ErrParameterValue},
		{name: "scrypt-n-not-power-of-two", id: ksf.Scrypt, parameters: []uint64{3, 8, 1}, expected: internalKSF.ErrParameterValue},
		{name: "scrypt-r-zero", id: ksf.Scrypt, parameters: []uint64{32768, 0, 1}, expected: internalKSF.ErrParameterValue},
		{name: "scrypt-p-zero", id: ksf.Scrypt, parameters: []uint64{32768, 8, 0}, expected: internalKSF.ErrParameterValue},
		{name: "pbkdf2-iterations-zero", id: ksf.PBKDF2Sha512, parameters: []uint64{0}, expected: internalKSF.ErrParameterValue},
		{name: "identity-parameters-not-allowed", id: 0, parameters: []uint64{1}, expected: internalKSF.ErrParameters},
	}

	for _, test := range tests {
		t.Run(test.name, func(t2 *testing.T) {
			options := internalKSF.NewOptions(32)
			expectErrors(t2, func() error {
				return options.Set(internalKSF.NewKSF(test.id), nil, test.parameters, 32)
			}, test.expected)
		})
	}
}
