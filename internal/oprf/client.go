// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from
// https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var errInvalidInput = errors.New("invalid input - OPRF input deterministically maps to the group identity element")

// Client implements the OPRF client and holds its state.
type Client struct {
	*oprf
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
		c.blind = c.NewScalar().Random()
	}

	p := c.HashToGroup(input, c.dst(tag.OPRFPointPrefix))
	if p.IsIdentity() {
		panic(errInvalidInput)
	}

	c.input = input

	return p.Mult(c.blind)
}

func (o *oprf) hash(input ...[]byte) []byte {
	h := suiteToHash[o.Group].New()
	h.Reset()

	for _, i := range input {
		_, _ = h.Write(i)
	}

	return h.Sum(nil)
}

func (o *oprf) hashTranscript(input, unblinded []byte) []byte {
	encInput := encoding.EncodeVector(input)
	encElement := encoding.EncodeVector(unblinded)
	encDST := []byte(tag.OPRFFinalize)

	return o.hash(encInput, encElement, encDST)
}

// Finalize terminates the OPRF by unblinding the evaluation and hashing the transcript.
func (c *Client) Finalize(evaluation *group.Point) []byte {
	u := encoding.SerializePoint(evaluation.InvertMult(c.blind), c.Group)
	return c.hashTranscript(c.input, u)
}
