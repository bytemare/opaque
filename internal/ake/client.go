// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ake

import (
	"errors"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidServerMac = errors.New("invalid server mac")

// Client exposes the client's AKE functions and holds its state.
type Client struct {
	values
	Ke1           []byte
	sessionSecret []byte
}

// NewClient returns a new, empty, 3DH client.
func NewClient() *Client {
	return &Client{
		values: values{
			ephemeralSecretKey: nil,
			nonce:              nil,
		},
		Ke1:           nil,
		sessionSecret: nil,
	}
}

// Start initiates the 3DH protocol, and returns a KE1 message with clientInfo.
func (c *Client) Start(cs group.Group, options Options) *message.KE1 {
	epk := c.values.setOptions(cs, options)

	return &message.KE1{
		G:                 cs,
		CredentialRequest: nil,
		NonceU:            c.nonce,
		EpkU:              epk,
	}
}

// Finalize verifies and responds to KE3. If the handshake is successful, the session key is stored and this functions
// returns a KE3 message.
func (c *Client) Finalize(
	conf *internal.Configuration,
	identities *Identities,
	clientSecretKey *group.Scalar,
	serverPublicKey *group.Element,
	ke2 *message.KE2,
) (*message.KE3, error) {
	ikm := k3dh(
		conf.Group,
		ke2.EpkS,
		c.ephemeralSecretKey,
		serverPublicKey,
		c.ephemeralSecretKey,
		ke2.EpkS,
		clientSecretKey,
	)
	sessionSecret, serverMac, clientMac := core3DH(conf, identities, ikm, c.Ke1, ke2)

	if !conf.MAC.Equal(serverMac, ke2.Mac) {
		return nil, errAkeInvalidServerMac
	}

	c.sessionSecret = sessionSecret

	return &message.KE3{Mac: clientMac}, nil
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (c *Client) SessionKey() []byte {
	return c.sessionSecret
}
