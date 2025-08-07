// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ksf provides the Key Stretching Functions.
package ksf

import (
	"errors"
	"fmt"

	"github.com/bytemare/ksf"
)

// ErrParameters indicates an invalid amount of KSF parameters.
var ErrParameters = errors.New("invalid number of KSF parameters")

// Options holds optional parameters to tweak the KSF and provide a custom salt.
type Options struct {
	Salt       []byte
	Parameters []int
	Length     int
}

// NewOptions returns a new Options instance with the provided length.
func NewOptions(length int) *Options {
	return &Options{
		Salt:       nil,
		Parameters: nil,
		Length:     length,
	}
}

// Set sets the options for the KSF. If parameters are provided, they must match the amount of canonical parameters.
func (o *Options) Set(f ksfInterface, salt []byte, parameters []int, length int) error {
	if len(parameters) != 0 {
		if len(parameters) != len(f.Parameters()) {
			return fmt.Errorf("%w: expected %d, got %d",
				ErrParameters, len(f.Parameters()), len(parameters))
		}

		o.Parameters = parameters
	} else {
		o.Parameters = f.Parameters()
	}

	if length < 0 {
		return fmt.Errorf("the provided KSF output length must not be negative: %q", length)
	}

	if length != 0 {
		o.Length = length
	}

	o.Salt = salt

	return nil
}

// KSF wraps a key stretching function and exposes its functions.
type KSF struct {
	ksfInterface
}

// NewKSF returns a newly instantiated KSF.
func NewKSF(id ksf.Identifier) *KSF {
	if id == 0 {
		return &KSF{&IdentityKSF{}}
	}

	return &KSF{id.Get()}
}

type ksfInterface interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int) []byte

	// Parameterize replaces the functions parameters with the new ones.
	// Must match the amount of parameters for the KSF.
	Parameterize(parameters ...int)

	// Parameters returns the list of internal parameters. If none were provided or modified,
	// the recommended defaults values are used.
	Parameters() []int
}

// IdentityKSF represents a KSF with no operations.
type IdentityKSF struct{}

// Harden returns the password as is.
func (i IdentityKSF) Harden(password, _ []byte, _ int) []byte {
	return password
}

// Parameterize applies KSF parameters if defined.
func (i IdentityKSF) Parameterize(_ ...int) {
	// no-op
}

// Parameters returns the list of internal parameters. If none were provided or modified,
// the recommended defaults values are used.
func (i IdentityKSF) Parameters() []int {
	// no-op
	return nil
}
