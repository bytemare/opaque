// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"slices"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

// Client represents an OPAQUE Client, exposing its methods and holding its state.
// The state includes the OPRF blind, during a registration or authentication session, and the ephemeral secret key
// share during an authentication session.
type Client struct {
	Deserialize *Deserializer
	conf        *internal.Configuration
	oprf        oprfState
	ake         akeState
}

type oprfState struct {
	blind    *ecc.Scalar // OPRF blind used in the registration or authentication phases.
	password []byte      // Password used in the registration and authentication phases.
}

type akeState struct {
	SecretKeyShare *ecc.Scalar // SecretKeyShare is the ephemeral secret key share used in the authentication phase.
	ke1            []byte      // KE1 message serialized, used in the authentication phase.
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
		Deserialize: &Deserializer{conf: conf},
		conf:        conf,
		oprf: oprfState{
			blind:    nil,
			password: nil,
		},
		ake: akeState{
			SecretKeyShare: nil,
			ke1:            nil,
		},
	}, nil
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
// This will initiate a state, so the same client instance should be used to call RegistrationFinalize() later on.
// Optionally, that value can be overridden by providing a ClientOptions with an OPRF Blind value, but at your own risks.
func (c *Client) RegistrationInit(
	password []byte,
	options ...*ClientOptions,
) (*message.RegistrationRequest, error) {
	if c.oprf.blind != nil {
		return nil, ErrClientState.Join(internal.ErrClientPreviousBlind)
	}

	var blind *ecc.Scalar
	var err error

	if len(options) != 0 {
		blind, err = c.verifyOptionBlind(options...)
		if err != nil {
			return nil, err
		}
	}

	var m *ecc.Element

	c.oprf.blind, m = c.conf.OPRF.Blind(password, blind)
	c.oprf.password = slices.Clone(password)

	return &message.RegistrationRequest{
		BlindedMessage: m,
	}, nil
}

// RegistrationFinalize returns a RegistrationRecord message given the identities and the server's RegistrationResponse,
// and the export key, that the client can use for other means.
func (c *Client) RegistrationFinalize(
	resp *message.RegistrationResponse,
	clientIdentity, serverIdentity []byte,
	options ...*ClientOptions,
) (record *message.RegistrationRecord, exportKey []byte, err error) {
	o, err := c.parseOptionsRegistrationFinalize(options)
	if err != nil {
		return nil, nil, err
	}

	if err = c.validateRegistrationResponse(resp); err != nil {
		return nil, nil, ErrRegistration.Join(err)
	}

	randomizedPassword := c.buildPRK(resp.EvaluatedMessage, o.KDFSalt, o.KSFOptions.Salt, o.KSFOptions.Length)
	maskingKey := c.conf.KDF.Expand(randomizedPassword, []byte(tag.MaskingKey), c.conf.KDF.Size())
	envelope, clientPublicKey, exportKey := keyrecovery.Store(
		c.conf,
		randomizedPassword,
		resp.ServerPublicKey,
		clientIdentity,
		serverIdentity,
		o.EnvelopeNonce,
	)

	// todo: note that this needs a confidential channel
	return &message.RegistrationRecord{
		ClientPublicKey: clientPublicKey,
		MaskingKey:      maskingKey,
		Envelope:        envelope.Serialize(),
	}, exportKey, nil
}

// GenerateKE1 initiates the authentication process, returning a KE1 message, blinding the given password. This method
// initiates a state, so the same client instance should be used to call GenerateKE3() later on.
// Alternatively, provide a OPRF Blind in the ClientOptions to use a custom blind value, and reuse the same blind when
// invoking GenerateKE3() for the same message but different client instances.
func (c *Client) GenerateKE1(password []byte, options ...*ClientOptions) (*message.KE1, error) {
	if c.oprf.blind != nil {
		return nil, ErrClientState.Join(internal.ErrClientPreviousBlind)
	}

	if c.ake.SecretKeyShare != nil {
		return nil, ErrClientState.Join(internal.ErrClientPreExistingKeyShare)
	}

	o, err := c.parseOptionsKE1(options)
	if err != nil {
		return nil, err
	}

	var m *ecc.Element

	c.oprf.blind, m = c.conf.OPRF.Blind(password, o.OPRFBlind)
	c.oprf.password = slices.Clone(password)
	ke1 := ake.Start(c.conf.Group, c.ake.SecretKeyShare, o.AKENonce)
	ke1.CredentialRequest.BlindedMessage = m
	c.ake.ke1 = ke1.Serialize()

	return ke1, nil
}

// GenerateKE3 returns a KE3 message given the server's KE2 response message and the identities. If the client or server
// identity parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) GenerateKE3(
	ke2 *message.KE2,
	clientIdentity, serverIdentity []byte,
	options ...*ClientOptions,
) (ke3 *message.KE3, sessionKey, exportKey []byte, err error) {
	if err = c.validateKE2(ke2); err != nil {
		return nil, nil, nil, err
	}

	o, err := c.parseOptionsKE3(options)
	if err != nil {
		return nil, nil, nil, err
	}

	// Finalize the OPRF.
	randomizedPassword := c.buildPRK(ke2.EvaluatedMessage, o.KDFSalt, o.KSFOptions.Salt, o.KSFOptions.Length)
	defer internal.ClearSlice(&randomizedPassword)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.conf, randomizedPassword, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, nil, ErrAuthentication.Join(internal.ErrAuthenticationInvalidServerPublicKey, err)
	}

	var clientSecretKey *ecc.Scalar
	defer internal.ClearScalar(&clientSecretKey)

	// Recover the client keys.
	clientSecretKey, clientPublicKey,
		exportKey, err := keyrecovery.Recover(
		c.conf,
		randomizedPassword,
		serverPublicKeyBytes,
		clientIdentity,
		serverIdentity,
		envelope)
	if err != nil {
		return nil, nil, nil, ErrAuthentication.Join(err)
	}

	// Finalize the AKE.
	identities := (&ake.Identities{
		ClientIdentity: clientIdentity,
		ServerIdentity: serverIdentity,
	}).SetIdentities(clientPublicKey, serverPublicKeyBytes)

	ke3, sessionKey, macOK := ake.Finalize(
		c.conf,
		clientSecretKey,
		c.ake.SecretKeyShare,
		identities,
		serverPublicKey,
		ke2,
		c.ake.ke1,
	)
	if !macOK {
		return nil, nil, nil, ErrAuthentication.Join(
			internal.ErrServerAuthentication,
			internal.ErrInvalidServerMac,
		)
	}

	return ke3, sessionKey, exportKey, nil
}

// ClearState attempts to zero out the client's secret material and state, and sets them to nil. It is strongly
// recommended to call this method after the client is done with the protocol, to avoid leaking sensitive key material.
func (c *Client) ClearState() {
	if c.ake.SecretKeyShare != nil {
		internal.ClearScalar(&c.ake.SecretKeyShare)
	}

	if len(c.ake.ke1) > 0 {
		internal.ClearSlice(&c.ake.ke1)
	}

	if c.oprf.blind != nil {
		internal.ClearScalar(&c.oprf.blind)
	}

	if len(c.oprf.password) > 0 {
		internal.ClearSlice(&c.oprf.password)
	}
}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *ecc.Element, kdfSalt, ksfSalt []byte, ksfLength int) []byte {
	output := c.conf.OPRF.Finalize(c.oprf.blind, c.oprf.password, evaluation)
	stretched := c.conf.KSF.Harden(output, ksfSalt, ksfLength)
	// todo: what happens if the unblinded output is all zeroes? (it will get hashed, but still?)
	return c.conf.KDF.Extract(kdfSalt, encoding.Concat(output, stretched))
}

func (c *Client) validateRegistrationResponse(resp *message.RegistrationResponse) error {
	if resp == nil {
		return ErrRegistrationResponse.Join(internal.ErrRegistrationResponseNil)
	}

	if resp.EvaluatedMessage == nil || len(resp.ServerPublicKey) == 0 {
		return ErrRegistrationResponse.Join(internal.ErrRegistrationResponseEmpty)
	}

	if err := IsValidElement(c.conf.Group, resp.EvaluatedMessage); err != nil {
		return ErrRegistrationResponse.Join(internal.ErrInvalidEvaluatedMessage, err)
	}

	if _, err := DeserializeElement(c.conf.Group, resp.ServerPublicKey); err != nil {
		return ErrRegistrationResponse.Join(internal.ErrInvalidServerPublicKey, internal.ErrInvalidPublicKeyBytes, err)
	}

	return nil
}

func (c *Client) validateCredentialResponse(cr *message.CredentialResponse) error {
	if cr == nil {
		return internal.ErrCredentialResponseNil
	}

	if err := IsValidElement(c.conf.Group, cr.EvaluatedMessage); err != nil {
		return errors.Join(internal.ErrCredentialResponseInvalid, internal.ErrInvalidEvaluatedMessage, err)
	}

	if len(cr.MaskingNonce) == 0 {
		return errors.Join(internal.ErrCredentialResponseInvalid, internal.ErrCredentialResponseNoMaskingNonce)
	}

	if isAllZeros(cr.MaskingNonce) {
		return errors.Join(internal.ErrCredentialResponseInvalid,
			internal.ErrCredentialResponseInvalidMaskingNonce, internal.ErrSliceIsAllZeros)
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	// todo: is this tested against?
	if len(cr.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return errors.Join(
			internal.ErrCredentialResponseInvalid,
			internal.ErrCredentialResponseInvalidMaskedResponse,
			internal.ErrInvalidEncodingLength,
		)
	}

	return nil
}

func (c *Client) validateKE2(ke2 *message.KE2) error {
	if ke2 == nil {
		return ErrKE2.Join(internal.ErrKE2Nil)
	}

	if err := c.validateCredentialResponse(ke2.CredentialResponse); err != nil {
		return ErrKE2.Join(err)
	}

	if ke2.ServerKeyShare == nil {
		return ErrKE2.Join(internal.ErrServerKeyShareMissing)
	}

	if err := IsValidElement(c.conf.Group, ke2.ServerKeyShare); err != nil {
		return ErrKE2.Join(internal.ErrInvalidServerKeyShare, err)
	}

	if len(ke2.ServerNonce) == 0 {
		return ErrKE2.Join(internal.ErrMissingNonce)
	}

	if isAllZeros(ke2.ServerNonce) {
		return ErrKE2.Join(internal.ErrMissingNonce, internal.ErrSliceIsAllZeros)
	}

	if len(ke2.ServerMac) == 0 {
		return ErrKE2.Join(internal.ErrMissingMAC)
	}

	if isAllZeros(ke2.ServerMac) {
		return ErrKE2.Join(internal.ErrMissingMAC, internal.ErrSliceIsAllZeros)
	}

	return nil
}
