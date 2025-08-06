// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package oprf

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var errInvalidInput = errors.New("invalid input - OPRF input deterministically maps to the group identity element")

// Blind masks the input.
func (i Identifier) Blind(input []byte, blind *ecc.Scalar) (*ecc.Scalar, *ecc.Element) {
	if blind == nil {
		blind = i.Group().NewScalar().Random()
	}

	p := i.Group().HashToGroup(input, i.dst(tag.OPRFPointPrefix))
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	return blind, p.Multiply(blind)
}

func (i Identifier) hashTranscript(input, unblinded []byte) []byte {
	encInput := encoding.EncodeVector(input)
	encElement := encoding.EncodeVector(unblinded)
	encDST := []byte(tag.OPRFFinalize)

	return i.hash(encInput, encElement, encDST)
}

// Finalize terminates the OPRF by unblinding the evaluation and hashing the transcript.
func (i Identifier) Finalize(blind *ecc.Scalar, input []byte, evaluation *ecc.Element) []byte {
	invert := blind.Copy().Invert()
	u := evaluation.Copy().Multiply(invert).Encode()

	return i.hashTranscript(input, u)
}
