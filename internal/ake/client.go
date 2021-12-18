// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidServerMac = errors.New("invalid server mac")

// Client exposes the client's AKE functions and holds its state.
type Client struct {
	esk           *group.Scalar
	Ke1           []byte
	sessionSecret []byte
	nonceU        []byte // testing: integrated to support testing, to force values.
}

// NewClient returns a new, empty, 3DH client.
func NewClient() *Client {
	return &Client{}
}

// SetValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func (c *Client) SetValues(id group.Group, esk *group.Scalar, nonce []byte, nonceLen int) *group.Point {
	s, nonce := setValues(id, esk, nonce, nonceLen)
	if c.esk == nil || (esk != nil && c.esk != s) {
		c.esk = s
	}

	if c.nonceU == nil {
		c.nonceU = nonce
	}

	return id.Base().Mult(c.esk)
}

// Start initiates the 3DH protocol, and returns a KE1 message with clientInfo.
func (c *Client) Start(cs group.Group) *message.KE1 {
	epk := c.SetValues(cs, nil, nil, 32)

	return &message.KE1{
		NonceU: c.nonceU,
		EpkU:   epk,
	}
}

// Finalize verifies and responds to KE3. If the handshake is successful, the session key is stored and this functions
// returns a KE3 message.
func (c *Client) Finalize(p *internal.Parameters, clientIdentity []byte, clientSecretKey *group.Scalar,
	serverIdentity []byte, serverPublicKey *group.Point, ke2 *message.KE2) (*message.KE3, error) {
	ikm := k3dh(p.Group, ke2.EpkS, c.esk, serverPublicKey, c.esk, ke2.EpkS, clientSecretKey)
	sessionSecret, serverMac, clientMac := core3DH(p, ikm, clientIdentity, serverIdentity, c.Ke1, ke2)

	if !p.MAC.Equal(serverMac, ke2.Mac) {
		return nil, errAkeInvalidServerMac
	}

	c.sessionSecret = sessionSecret

	return &message.KE3{Mac: clientMac}, nil
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (c *Client) SessionKey() []byte {
	return c.sessionSecret
}
