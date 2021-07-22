// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/envelope"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// errInvalidPKS happens when the server sends an invalid public key on registration.
	errInvalidPKS = errors.New("invalid server public key")
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	Core *envelope.Core
	Ake  *ake.Client
	Ke1  *message.KE1
	*internal.Parameters
	mode envelope.Mode
}

// NewClient returns a new Client instantiation given the application Configuration.
func NewClient(p *Configuration) *Client {
	if p == nil {
		p = DefaultConfiguration()
	}

	ip := p.toInternal()

	return &Client{
		Core:       envelope.New(ip),
		Ake:        ake.NewClient(),
		Parameters: ip,
		mode:       envelope.Mode(p.Mode),
	}
}

// KeyGen returns a key pair in the AKE group. It can then be used for the external mode.
func (c *Client) KeyGen() (secretKey, publicKey []byte) {
	return ake.KeyGen(c.AKEGroup)
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(password []byte) *message.RegistrationRequest {
	m := c.Core.OprfStart(password)
	return &message.RegistrationRequest{Data: m}
}

// RegistrationFinalize returns a RegistrationUpload message given the server's RegistrationResponse and credentials. If
// the envelope mode is internal, then clientSecretKey is ignored and can be set to nil. For the external
// mode, clientSecretKey must be the client's private key for the AKE.
func (c *Client) RegistrationFinalize(clientSecretKey []byte, creds *Credentials,
	resp *message.RegistrationResponse) (upload *message.RegistrationUpload, exportKey []byte, err error) {
	creds2 := &envelope.Credentials{
		Idc:           creds.Client,
		Ids:           creds.Server,
		EnvelopeNonce: creds.TestEnvNonce,
		MaskingNonce:  creds.TestMaskNonce,
	}

	// this check is very important
	if _, err = c.AKEGroup.Get().NewElement().Decode(resp.Pks); err != nil {
		return nil, nil, fmt.Errorf("%s : %w", errInvalidPKS, err)
	}

	envU, clientPublicKey, maskingKey, exportKey, err := c.Core.BuildEnvelope(c.mode, resp.Data, resp.Pks, clientSecretKey, creds2)
	if err != nil {
		return nil, nil, fmt.Errorf("building envelope: %w", err)
	}

	return &message.RegistrationUpload{
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envU.Serialize(),
	}, exportKey, nil
}

// Init initiates the authentication process, returning a KE1 message blinding the given password.
// clientInfo is optional client information sent in clear, and only authenticated in KE3.
func (c *Client) Init(password []byte) *message.KE1 {
	m := c.Core.OprfStart(password)
	credReq := &cred.CredentialRequest{Data: encoding.PadPoint(m, c.Parameters.OprfCiphersuite.Group())}
	c.Ke1 = c.Ake.Start(c.Parameters.AKEGroup)
	c.Ke1.CredentialRequest = credReq

	return c.Ke1
}

// unmask assumes that maskedResponse has been checked to be of length pointLength + envelope size.
func (c *Client) unmask(maskingNonce, maskingKey, maskedResponse []byte) ([]byte, *envelope.Envelope) {
	clear := c.MaskResponse(maskingKey, maskingNonce, maskedResponse)
	serverPublicKey := clear[:encoding.PointLength[c.AKEGroup]]
	e := clear[encoding.PointLength[c.AKEGroup]:]

	// Deserialize
	innerLen := 0

	if c.mode == envelope.External {
		innerLen = encoding.ScalarLength[c.AKEGroup]
	}

	env := &envelope.Envelope{
		Nonce:         e[:c.NonceLen],
		InnerEnvelope: e[c.NonceLen : c.NonceLen+innerLen],
		AuthTag:       e[c.NonceLen+innerLen:],
	}

	return serverPublicKey, env
}

// Finish returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) Finish(idc, ids []byte, ke2 *message.KE2) (ke3 *message.KE3, exportKey []byte, err error) {
	unblinded, err := c.Core.OprfFinalize(ke2.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != encoding.PointLength[c.AKEGroup]+c.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	randomizedPwd := envelope.BuildPRK(c.Parameters, unblinded)
	maskingKey := c.Core.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), c.Core.Hash.Size())

	serverPublicKey, env := c.unmask(ke2.MaskingNonce, maskingKey, ke2.MaskedResponse)

	m := &envelope.Mailer{Parameters: c.Parameters}

	clientSecretKey, clientPublicKey, exportKey, err := m.RecoverEnvelope(c.mode, randomizedPwd, serverPublicKey, idc, ids, env)
	if err != nil {
		return nil, nil, fmt.Errorf("recover envelope: %w", err)
	}

	if idc == nil {
		idc = clientPublicKey.Bytes()
	}

	if ids == nil {
		ids = serverPublicKey
	}

	ke3, err = c.Ake.Finalize(c.Parameters, idc, clientSecretKey, ids, serverPublicKey, c.Ke1, ke2)
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
