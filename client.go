// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/masking"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// errKe1Missing happens when LoginFinish is called and the client has no Ke1 in state.
	errKe1Missing = errors.New("missing KE1 in client")
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	OPRF *oprf.Client
	Ake  *ake.Client
	*internal.Parameters
}

// NewClient returns a new Client instantiation given the application Configuration.
func NewClient(p *Configuration) (*Client, error) {
	if p == nil {
		p = DefaultConfiguration()
	}

	ip, err := p.toInternal()
	if err != nil {
		return nil, err
	}

	return &Client{
		OPRF:       ip.OPRF.Client(),
		Ake:        ake.NewClient(),
		Parameters: ip,
	}, nil
}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *group.Point) []byte {
	output := c.OPRF.Finalize(evaluation)
	stretched := c.KSF.Harden(output, nil, c.OPRFPointLength)

	return c.KDF.Extract(nil, encoding.Concat(output, stretched))
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(password []byte) *message.RegistrationRequest {
	m := c.OPRF.Blind(password)
	return &message.RegistrationRequest{BlindedMessage: m}
}

// RegistrationFinalizeWithNonce returns a RegistrationRecord message given the identities, server's RegistrationResponse,
// and the envelope nonce to be used.
// This function is primarily used for testing purposes and will most probably be removed at some point.
func (c *Client) RegistrationFinalizeWithNonce(resp *message.RegistrationResponse, idc, ids, envelopeNonce []byte) (upload *message.RegistrationRecord, exportKey []byte) {
	return c.registrationFinalize(idc, ids, envelopeNonce, resp)
}

// RegistrationFinalize returns a RegistrationRecord message given the identities and the server's RegistrationResponse.
func (c *Client) RegistrationFinalize(resp *message.RegistrationResponse, idc, ids []byte) (upload *message.RegistrationRecord, exportKey []byte) {
	return c.registrationFinalize(idc, ids, nil, resp)
}

func (c *Client) registrationFinalize(idc, ids, envelopeNonce []byte, resp *message.RegistrationResponse) (upload *message.RegistrationRecord, exportKey []byte) {
	creds2 := &keyrecovery.Credentials{
		Idc:           idc,
		Ids:           ids,
		EnvelopeNonce: envelopeNonce,
	}

	// this check is very important: it verifies the server's public key validity in the group.
	// if _, err := c.Group.NewElement().Decode(resp.Pks); err != nil {
	//	return nil, nil, fmt.Errorf("%s : %w", errInvalidPKS, err)
	// }

	randomizedPwd := c.buildPRK(resp.EvaluatedMessage)
	maskingKey := c.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), c.KDF.Size())
	envU, clientPublicKey, exportKey := keyrecovery.Store(c.Parameters, randomizedPwd, encoding.SerializePoint(resp.Pks, c.Group), creds2)

	return &message.RegistrationRecord{
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envU.Serialize(),
	}, exportKey
}

// LoginInit initiates the authentication process, returning a KE1 message blinding the given password.
// clientInfo is optional client information sent in clear, and only authenticated in KE3.
func (c *Client) LoginInit(password []byte) *message.KE1 {
	m := c.OPRF.Blind(password)
	credReq := &cred.CredentialRequest{BlindedMessage: m}
	ke1 := c.Ake.Start(c.Group)
	ke1.CredentialRequest = credReq
	c.Ake.Ke1 = ke1.Serialize()

	return ke1
}

// LoginFinish returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) LoginFinish(idc, ids []byte, ke2 *message.KE2) (ke3 *message.KE3, exportKey []byte, err error) {
	if len(c.Ake.Ke1) == 0 {
		return nil, nil, errKe1Missing
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.AkePointLength+c.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	// Finalize the OPRF.
	randomizedPwd := c.buildPRK(ke2.EvaluatedMessage)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.Parameters, randomizedPwd, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, err
	}

	// Recover the client keys.
	clientSecretKey, clientPublicKey,
		exportKey, err := keyrecovery.Recover(c.Parameters, randomizedPwd, serverPublicKeyBytes, idc, ids, envelope)
	if err != nil {
		return nil, nil, err
	}

	// Finalize the AKE.
	if idc == nil {
		idc = encoding.SerializePoint(clientPublicKey, c.Group)
	}

	if ids == nil {
		ids = serverPublicKeyBytes
	}

	ke3, err = c.Ake.Finalize(c.Parameters, idc, clientSecretKey, ids, serverPublicKey, ke2)
	if err != nil {
		return nil, nil, err
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to LoginFinish() was successful.
func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}

// DeserializeKE1 takes a serialized KE1 message and returns a deserialized KE1 structure.
func (c *Client) DeserializeKE1(ke1 []byte) (*message.KE1, error) {
	return c.Parameters.DeserializeKE1(ke1)
}

// DeserializeKE2 takes a serialized KE2 message and returns a deserialized KE2 structure.
func (c *Client) DeserializeKE2(ke2 []byte) (*message.KE2, error) {
	return c.Parameters.DeserializeKE2(ke2)
}

// DeserializeKE3 takes a serialized KE3 message and returns a deserialized KE3 structure.
func (c *Client) DeserializeKE3(ke3 []byte) (*message.KE3, error) {
	return c.Parameters.DeserializeKE3(ke3)
}
