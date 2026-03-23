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

	"github.com/bytemare/ksf"
)

var (
	// ErrParameters indicates invalid KSF parameters.
	ErrParameters = errors.New("invalid KSF parameters")

	// ErrNegativeKSFLength indicates that the requested KSF output length is negative.
	ErrNegativeKSFLength = errors.New("the requested KSF output length is negative")

	// ErrUnexpectedIdentityParameters indicates that parameters were provided for the Identity KSF,
	// which does not take any parameters.
	ErrUnexpectedIdentityParameters = errors.New("unexpected parameters with the Identity KSF")
)

// Parameters holds optional parameters to tweak the KSF and provide a custom salt.
type Parameters struct {
	Salt       []byte
	Parameters []uint64
	Length     int
}

// NewParameters returns a new Parameters instance with the provided length.
func NewParameters(length int) *Parameters {
	return &Parameters{
		Salt:       nil,
		Parameters: nil,
		Length:     length,
	}
}

// Set sets the options for the KSF. If parameters are provided, they must match the KSF shape and value constraints.
func (o *Parameters) Set(f KSF, salt []byte, parameters []uint64, length int) error {
	if length < 0 {
		return ErrNegativeKSFLength
	}

	defaults := f.DefaultParameters()

	if len(parameters) == 0 {
		o.Parameters = append([]uint64(nil), defaults...)
	} else {
		if err := f.VerifyParameters(parameters...); err != nil {
			return errors.Join(ErrParameters, err)
		}

		o.Parameters = make([]uint64, len(parameters))
		copy(o.Parameters, parameters)
	}

	if length != 0 {
		o.Length = length
	}

	o.Salt = salt

	return nil
}

// KSF is a key stretching function.
type KSF interface {
	// Harden uses default parameters for the key derivation function over the input password and salt.
	Harden(password, salt []byte, length int, parameters ...uint64) ([]byte, error)

	// UnsafeHarden is the same as Harden but panics if the KSF identifier is not
	// recognized or the parameters are invalid, and does not return an error.
	// It is the caller's responsibility to ensure that the parameters are valid for the KSF.
	UnsafeHarden(password, salt []byte, length int, parameters ...uint64) []byte

	// VerifyParameters checks whether the provided parameters are valid for the  KSF specified by the identifier.
	VerifyParameters(parameters ...uint64) error

	// DefaultParameters returns the list of default recommended parameters.
	DefaultParameters() []uint64
}

// IdentityKSF represents a KSF with no operations.
type IdentityKSF ksf.Identifier

// Harden returns the password as is.
func (i IdentityKSF) Harden(password, _ []byte, _ int, _ ...uint64) ([]byte, error) {
	return password, nil
}

// UnsafeHarden is the same as Harden but panics if the KSF identifier is not
// recognized or the parameters are invalid, and does not return an error.
// It is the caller's responsibility to ensure that the parameters are valid for the KSF.
func (i IdentityKSF) UnsafeHarden(password, _ []byte, _ int, _ ...uint64) []byte {
	return password
}

// VerifyParameters fails if any arguments are provided, since the IdentityKSF does not take any parameters.
func (i IdentityKSF) VerifyParameters(parameters ...uint64) error {
	if len(parameters) != 0 {
		return errors.Join(ErrParameters, ErrUnexpectedIdentityParameters)
	}

	return nil
}

// DefaultParameters returns the list of default recommended parameters.
func (i IdentityKSF) DefaultParameters() []uint64 {
	// no-op
	return nil
}
