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
	"fmt"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// errInvalidPKS happens when the server sends an invalid public key.
	errInvalidPKS = errors.New("invalid server public key")
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	OPRF *oprf.Client
	Ake  *ake.Client
	Ke1  *message.KE1
	*internal.Parameters
}

// NewClient returns a new Client instantiation given the application Configuration.
func NewClient(p *Configuration) *Client {
	if p == nil {
		p = DefaultConfiguration()
	}

	ip := p.toInternal()

	return &Client{
		OPRF:       ip.OPRF.Client(),
		Ake:        ake.NewClient(),
		Parameters: ip,
	}
}

// KeyGen returns a key pair in the AKE group. It can then be used for the external mode.
func (c *Client) KeyGen() (secretKey, publicKey []byte) {
	return ake.KeyGen(c.Group)
}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *group.Point, info []byte) ([]byte, error) {
	unblinded, err := c.OPRF.Finalize(evaluation, info)
	if err != nil {
		return nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	hardened := c.MHF.Harden(unblinded, nil, c.OPRFPointLength)

	return c.KDF.Extract(nil, encoding.Concat(unblinded, hardened)), nil
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(password []byte) *message.RegistrationRequest {
	m := c.OPRF.Blind(password)
	return &message.RegistrationRequest{Data: m}
}

// RegistrationFinalize returns a RegistrationRecord message given the server's RegistrationResponse and credentials. If
// the envelope mode is internal, then clientSecretKey is ignored and can be set to nil. For the external
// mode, clientSecretKey must be the client's private key for the AKE.
func (c *Client) RegistrationFinalize(creds *Credentials,
	resp *message.RegistrationResponse) (upload *message.RegistrationRecord, exportKey []byte, err error) {
	creds2 := &keyrecovery.Credentials{
		Idc:           creds.Client,
		Ids:           creds.Server,
		EnvelopeNonce: creds.TestEnvNonce,
		MaskingNonce:  creds.TestMaskNonce,
	}

	// this check is very important: it verifies the server's public key validity in the group.
	// if _, err = c.Group.NewElement().Decode(resp.Pks); err != nil {
	// 	return nil, nil, fmt.Errorf("%s : %w", errInvalidPKS, err)
	// }

	randomizedPwd, err := c.buildPRK(resp.Data, c.Info)
	if err != nil {
		return nil, nil, err
	}

	maskingKey := c.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), c.KDF.Size())
	envU, clientPublicKey, exportKey := keyrecovery.Store(c.Parameters, randomizedPwd, resp.Pks.Bytes(), creds2)

	return &message.RegistrationRecord{
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envU.Serialize(),
	}, exportKey, nil
}

// Init initiates the authentication process, returning a KE1 message blinding the given password.
// clientInfo is optional client information sent in clear, and only authenticated in KE3.
func (c *Client) Init(password []byte) *message.KE1 {
	m := c.OPRF.Blind(password)
	credReq := &cred.CredentialRequest{Data: m}
	c.Ke1 = c.Ake.Start(c.Group)
	c.Ke1.CredentialRequest = credReq

	return c.Ke1
}

// unmask assumes that maskedResponse has been checked to be of length pointLength + envelope size.
func (c *Client) unmask(maskingNonce, randomizedPwd, maskedResponse []byte) ([]byte, *keyrecovery.Envelope) {
	maskingKey := c.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), c.Hash.Size())
	clear := c.MaskResponse(maskingKey, maskingNonce, maskedResponse)
	serverPublicKey := clear[:encoding.PointLength[c.Group]]
	e := clear[encoding.PointLength[c.Group]:]
	env := &keyrecovery.Envelope{
		Nonce:   e[:c.NonceLen],
		AuthTag: e[c.NonceLen:],
	}

	return serverPublicKey, env
}

// Finish returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) Finish(idc, ids []byte, ke2 *message.KE2) (ke3 *message.KE3, exportKey []byte, err error) {
	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != encoding.PointLength[c.Group]+c.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	randomizedPwd, err := c.buildPRK(ke2.Data, c.Info)
	if err != nil {
		return nil, nil, err
	}

	serverPublicKey, env := c.unmask(ke2.MaskingNonce, randomizedPwd, ke2.MaskedResponse)

	pks, err := c.Group.NewElement().Decode(serverPublicKey)
	if err != nil {
		return nil, nil, errInvalidPKS
	}

	clientSecretKey, clientPublicKey, exportKey, err := keyrecovery.Recover(c.Parameters,
		randomizedPwd, serverPublicKey, idc, ids, env)
	if err != nil {
		return nil, nil, fmt.Errorf("recover envelope: %w", err)
	}

	if idc == nil {
		idc = clientPublicKey.Bytes()
	}

	if ids == nil {
		ids = serverPublicKey
	}

	ke3, err = c.Ake.Finalize(c.Parameters, idc, clientSecretKey, ids, pks, c.Ke1, ke2)
	if err != nil {
		return nil, nil, fmt.Errorf(" AKE finalization: %w", err)
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to Finish() was successful.
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
