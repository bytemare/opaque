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

	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var errInvalidInput = errors.New("invalid input - OPRF input deterministically maps to the group identity element")

// Client implements the OPRF client and holds its state.
type Client struct {
	blind *group.Scalar
	input []byte
	Ciphersuite
}

// SetBlind allows to set the blinding scalar to use.
func (c *Client) SetBlind(blind *group.Scalar) {
	c.blind = blind
}

// Blind masks the input.
func (c *Client) Blind(input []byte) *group.Element {
	if c.blind == nil {
		c.blind = c.Group().NewScalar().Random()
	}

	p := c.Group().HashToGroup(input, c.dst(tag.OPRFPointPrefix))
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	c.input = input

	return p.Multiply(c.blind)
}

func (c *Client) hashTranscript(input, unblinded []byte) []byte {
	encInput := encoding.EncodeVector(input)
	encElement := encoding.EncodeVector(unblinded)
	encDST := []byte(tag.OPRFFinalize)

	return c.Ciphersuite.hash(encInput, encElement, encDST)
}

// Finalize terminates the OPRF by unblinding the evaluation and hashing the transcript.
func (c *Client) Finalize(evaluation *group.Element) []byte {
	invert := c.blind.Copy().Invert()
	u := encoding.SerializePoint(evaluation.Copy().Multiply(invert), c.Ciphersuite.Group())

	return c.hashTranscript(c.input, u)
}
