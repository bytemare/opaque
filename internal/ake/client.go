// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ake

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidServerMac = errors.New("invalid server mac")

// Client exposes the client's AKE functions and holds its state.
type Client struct {
	EphemeralSecretKey *ecc.Scalar
	Ke1                []byte
	sessionSecret      []byte
}

// NewClient returns a new, empty, 3DH client.
func NewClient() *Client {
	return &Client{
		EphemeralSecretKey: nil,
		Ke1:                nil,
		sessionSecret:      nil,
	}
}

// Start initiates the 3DH protocol, and returns a KE1 message with clientInfo.
func (c *Client) Start(g ecc.Group, options *Options) *message.KE1 {
	esk, epk := MakeKeyShare(g, options.EphemeralKeyShareSeed, options.EphemeralSecretKeyShare)
	c.EphemeralSecretKey = esk

	return &message.KE1{
		CredentialRequest:    nil,
		ClientNonce:          options.Nonce,
		ClientPublicKeyshare: epk,
	}
}

// Finalize verifies and responds to KE3. If the handshake is successful, the session key is stored and this functions
// returns a KE3 message.
func (c *Client) Finalize(
	conf *internal.Configuration,
	ke2 *message.KE2,
	clientKM, serverKM *KeyMaterial,
) (*message.KE3, error) {
	ikm := k3dh(
		serverKM.PublicKeyShare,
		clientKM.EphemeralSecretKey,
		serverKM.PublicKey,
		clientKM.EphemeralSecretKey,
		serverKM.PublicKeyShare,
		clientKM.SecretKey,
	)
	sessionSecret, serverMac, clientMac := core3DH(conf, clientKM.Identity, serverKM.Identity, ikm, c.Ke1, ke2)

	if !conf.MAC.Equal(serverMac, ke2.ServerMac) {
		return nil, errAkeInvalidServerMac
	}

	c.sessionSecret = sessionSecret

	return &message.KE3{ClientMac: clientMac}, nil
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (c *Client) SessionKey() []byte {
	return c.sessionSecret
}

func (c *Client) GetEphemeralSecretKey() *ecc.Scalar {
	if c.EphemeralSecretKey == nil {
		return nil
	}
	return c.EphemeralSecretKey.Copy()
}

// Flush sets all the client's session related internal AKE values to nil.
func (c *Client) Flush() {
	if c.EphemeralSecretKey != nil {
		c.EphemeralSecretKey.Zero()
		c.EphemeralSecretKey = nil
	}

	c.Ke1 = nil
	c.sessionSecret = nil
}
