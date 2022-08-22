// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"

	group "github.com/bytemare/crypto"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// errKe1Missing happens when LoginFinish is called and the client has no Ke1 in state.
	errKe1Missing = errors.New("missing KE1 in client state")
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	Deserialize *Deserializer
	OPRF        *oprf.Client
	Ake         *ake.Client
	conf        *internal.Configuration
}

// NewClient returns a new Client instantiation given the application Configuration.
func NewClient(c *Configuration) (*Client, error) {
	if c == nil {
		c = DefaultConfiguration()
	}

	conf, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	return &Client{
		OPRF:        conf.OPRF.Client(),
		Ake:         ake.NewClient(),
		Deserialize: &Deserializer{conf: conf},
		conf:        conf,
	}, nil
}

// GetConf returns the internal configuration.
func (c *Client) GetConf() *internal.Configuration {
	return c.conf
}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *group.Element) []byte {
	output := c.OPRF.Finalize(evaluation)
	stretched := c.conf.KSF.Harden(output, nil, c.conf.OPRFPointLength)

	return c.conf.KDF.Extract(nil, encoding.Concat(output, stretched))
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(password []byte) *message.RegistrationRequest {
	m := c.OPRF.Blind(password)

	return &message.RegistrationRequest{
		C:              c.conf.OPRF,
		BlindedMessage: m,
	}
}

// RegistrationFinalizeWithNonce returns a RegistrationRecord message given the identities, server's
// RegistrationResponse, and the envelope nonce to be used.
// This function is primarily used for testing purposes and will most probably be removed at some point.
func (c *Client) RegistrationFinalizeWithNonce(
	resp *message.RegistrationResponse,
	clientIdentity, serverIdentity, envelopeNonce []byte,
) (upload *message.RegistrationRecord, exportKey []byte) {
	return c.registrationFinalize(clientIdentity, serverIdentity, envelopeNonce, resp)
}

// RegistrationFinalize returns a RegistrationRecord message given the identities and the server's RegistrationResponse.
func (c *Client) RegistrationFinalize(
	resp *message.RegistrationResponse,
	clientIdentity, serverIdentity []byte,
) (record *message.RegistrationRecord, exportKey []byte) {
	return c.registrationFinalize(clientIdentity, serverIdentity, nil, resp)
}

func (c *Client) registrationFinalize(
	clientIdentity, serverIdentity, envelopeNonce []byte,
	resp *message.RegistrationResponse,
) (upload *message.RegistrationRecord, exportKey []byte) {
	creds2 := &keyrecovery.Credentials{
		ClientIdentity: clientIdentity,
		ServerIdentity: serverIdentity,
		EnvelopeNonce:  envelopeNonce,
	}

	randomizedPwd := c.buildPRK(resp.EvaluatedMessage)
	maskingKey := c.conf.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), c.conf.KDF.Size())
	envelope, clientPublicKey, exportKey := keyrecovery.Store(c.conf, randomizedPwd, resp.Pks, creds2)

	return &message.RegistrationRecord{
		G:          c.conf.Group,
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envelope.Serialize(),
	}, exportKey
}

// LoginInit initiates the authentication process, returning a KE1 message blinding the given password.
// clientInfo is optional client information sent in clear, and only authenticated in KE3.
func (c *Client) LoginInit(password []byte) *message.KE1 {
	m := c.OPRF.Blind(password)
	ke1 := c.Ake.Start(c.conf.Group)
	ke1.CredentialRequest = message.NewCredentialRequest(c.conf.OPRF, m)
	c.Ake.Ke1 = ke1.Serialize()

	return ke1
}

// LoginFinish returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) LoginFinish(
	clientIdentity, serverIdentity []byte,
	ke2 *message.KE2,
) (ke3 *message.KE3, exportKey []byte, err error) {
	if len(c.Ake.Ke1) == 0 {
		return nil, nil, errKe1Missing
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.conf.AkePointLength+c.conf.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	// Finalize the OPRF.
	randomizedPwd := c.buildPRK(ke2.EvaluatedMessage)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.conf, randomizedPwd, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, err
	}

	// Recover the client keys.
	clientSecretKey, clientPublicKey,
		exportKey, err := keyrecovery.Recover(
		c.conf,
		randomizedPwd,
		serverPublicKeyBytes,
		clientIdentity,
		serverIdentity,
		envelope)
	if err != nil {
		return nil, nil, err
	}

	// Finalize the AKE.
	if clientIdentity == nil {
		clientIdentity = encoding.SerializePoint(clientPublicKey, c.conf.Group)
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKeyBytes
	}

	ke3, err = c.Ake.Finalize(c.conf, clientIdentity, clientSecretKey, serverIdentity, serverPublicKey, ke2)
	if err != nil {
		return nil, nil, err
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to LoginFinish() was successful.
func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
