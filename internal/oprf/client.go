// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"fmt"

	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/opaque/internal/encoding"
)

const dstFinalizePrefix = "Finalize-"

type Client struct {
	*oprf
	input []byte
	blind group.Scalar
}

func (c *Client) SetBlind(blind group.Scalar) {
	c.blind = blind
}

func (c *Client) Blind(input []byte) []byte {
	if c.blind == nil {
		c.blind = c.group.NewScalar().Random()
	}

	p := c.group.HashToGroup(input, c.dst(hash2groupDSTPrefix))
	c.input = input

	return p.Mult(c.blind).Bytes()
}

func (o *oprf) hashTranscript(input, unblinded []byte) []byte {
	finalizeDST := o.dst(dstFinalizePrefix)
	encInput := encoding.EncodeVector(input)
	encElement := encoding.EncodeVector(unblinded)
	encDST := encoding.EncodeVector(finalizeDST)

	return o.hash.Hash(encInput, encElement, encDST)
}

func (c *Client) Finalize(evaluation []byte) ([]byte, error) {
	ev, err := c.group.NewElement().Decode(evaluation)
	if err != nil {
		return nil, fmt.Errorf("could not decode element : %w", err)
	}

	return c.hashTranscript(c.input, ev.InvertMult(c.blind).Bytes()), nil
}
