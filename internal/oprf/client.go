// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package oprf

import (
	"errors"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"

	"github.com/bytemare/crypto/group"
)

var errInvalidInput = errors.New("invalid input - OPRF input deterministically maps to the group identity element")

// Client implements the OPRF client and holds its state.
type Client struct {
	Ciphersuite
	input []byte
	blind *group.Scalar
}

// SetBlind allows to set the blinding scalar to use.
func (c *Client) SetBlind(blind *group.Scalar) {
	c.blind = blind
}

// Blind masks the input.
func (c *Client) Blind(input []byte) *group.Point {
	if c.blind == nil {
		c.blind = c.Group().NewScalar().Random()
	}

	p := c.Group().HashToGroup(input, c.dst(tag.OPRFPointPrefix))
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	c.input = input

	return p.Mult(c.blind)
}

func (c *Client) hashTranscript(input, unblinded []byte) []byte {
	encInput := encoding.EncodeVector(input)
	encElement := encoding.EncodeVector(unblinded)
	encDST := []byte(tag.OPRFFinalize)

	return c.Ciphersuite.hash(encInput, encElement, encDST)
}

// Finalize terminates the OPRF by unblinding the evaluation and hashing the transcript.
func (c *Client) Finalize(evaluation *group.Point) []byte {
	u := encoding.SerializePoint(evaluation.InvertMult(c.blind), c.Ciphersuite.Group())
	return c.hashTranscript(c.input, u)
}
