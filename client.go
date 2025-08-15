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

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/ksf"
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

type oprfState struct {
	blind    *ecc.Scalar // OPRF blind used in the registration or authentication process.
	password []byte      // Password used in the registration and authentication process.
}

type akeState struct {
	esk *ecc.Scalar // esk is the ephemeral secret key share used in the authentication process.
	ke1 []byte      // KE1 message serialized, used in the authentication process.
}

// Client represents an OPAQUE Client, exposing its methods and holding its state.
// The state includes the OPRF blind, during a registration or authentication session, and the ephemeral secret key
// share during an authentication session.
type Client struct {
	Deserialize *Deserializer
	conf        *internal.Configuration
	oprf        oprfState
	ake         akeState
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
			esk: nil,
			ke1: nil,
		},
	}, nil
}

// ClientOptions override the secure default values or internally generated values.
// Only use this if you know what you're doing. Reusing seeds and nonces across sessions is a security risk,
// and breaks forward secrecy.
type ClientOptions struct {
	OPRFBlind           *ecc.Scalar
	AKE                 *AKEOptions
	KE1                 []byte
	KSFSalt             []byte
	EnvelopeNonce       []byte
	KDFSalt             []byte
	KSFParameters       []int
	EnvelopeNonceLength int
	KSFLength           int
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
	c.oprf.password = password

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

	if c.ake.esk != nil {
		return nil, ErrClientState.Join(internal.ErrClientPreExistingKeyShare)
	}

	o, err := c.parseOptionsKE1(options)
	if err != nil {
		return nil, err
	}

	var m *ecc.Element

	c.oprf.blind, m = c.conf.OPRF.Blind(password, o.OPRFBlind)
	c.oprf.password = password
	ke1 := ake.Start(c.conf.Group, c.ake.esk, o.AKENonce)
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
	defer internal.ClearSlice(randomizedPassword)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.conf, randomizedPassword, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, nil, ErrAuthentication.Join(internal.ErrAuthenticationInvalidServerPublicKey, err)
	}

	var clientSecretKey *ecc.Scalar
	defer internal.ClearScalar(clientSecretKey)

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
		c.ake.esk,
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
	if c.ake.esk != nil {
		internal.ClearScalar(c.ake.esk)
		c.ake.esk = nil
	}

	if c.oprf.blind != nil {
		internal.ClearScalar(c.oprf.blind)
		c.oprf.blind = nil
	}

	if len(c.oprf.password) > 0 {
		internal.ClearSlice(c.oprf.password)
		c.oprf.password = nil
	}
}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *ecc.Element, kdfSalt, ksfSalt []byte, ksfLength int) []byte {
	output := c.conf.OPRF.Finalize(c.oprf.blind, c.oprf.password, evaluation)
	stretched := c.conf.KSF.Harden(output, ksfSalt, ksfLength)
	// todo: what happens if the unblinded output is all zeroes? (it will get hashed, but still?)
	return c.conf.KDF.Extract(kdfSalt, encoding.Concat(output, stretched))
}

func (c *Client) verifyOptionBlind(clientOptions ...*ClientOptions) (*ecc.Scalar, error) {
	if clientOptions[0].OPRFBlind != nil {
		if err := IsValidScalar(c.conf.OPRF.Group(), clientOptions[0].OPRFBlind); err != nil {
			return nil, ErrClientOptions.Join(internal.ErrInvalidOPRFBlind, err)
		}
	}

	return clientOptions[0].OPRFBlind, nil
}

func getEnvelopeNonce(clientOptions ...*ClientOptions) ([]byte, error) {
	if len(clientOptions) == 0 {
		return internal.RandomBytes(internal.NonceLength), nil
	}

	nonce := clientOptions[0].EnvelopeNonce
	nonceLength := clientOptions[0].EnvelopeNonceLength

	if err := internal.ValidateOptionsLength(nonce, nonceLength, internal.NonceLength); err != nil {
		return nil, ErrClientOptions.Join(internal.ErrEnvelopeNonceOptions, err)
	}

	if nonce == nil {
		if nonceLength == 0 {
			nonceLength = internal.NonceLength
		}

		nonce = internal.RandomBytes(nonceLength)
	}

	return nonce, nil
}

type clientOptions struct {
	OPRFBlind     *ecc.Scalar
	KSFOptions    *ksf.Options
	EnvelopeNonce []byte
	KDFSalt       []byte
	AKENonce      []byte
}

func (c *Client) clientOptionsKSFParser(out *clientOptions, in *ClientOptions) error {
	if err := out.KSFOptions.Set(c.conf.KSF, in.KSFSalt, in.KSFParameters, in.KSFLength); err != nil {
		return ErrClientOptions.Join(err)
	}

	if len(out.KSFOptions.Parameters) != 0 {
		c.conf.KSF.Parameterize(out.KSFOptions.Parameters...)
	}

	return nil
}

// clientOptionsKE1Parser parses the KE1 options from the ClientOptions.
func (c *Client) clientOptionsKE1Parser(in *ClientOptions) error {
	if len(c.ake.ke1) != 0 {
		if len(in.KE1) != 0 {
			return ErrClientOptions.Join(internal.ErrDoubleKE1)
		}

		return nil
	}

	if len(in.KE1) == 0 {
		return ErrClientOptions.Join(internal.ErrKE1Missing)
	}

	if _, err := c.Deserialize.KE1(in.KE1); err != nil {
		return ErrClientOptions.Join(err)
	}

	c.ake.ke1 = in.KE1

	return nil
}

func (c *Client) parseOptionsRegistrationFinalize(options []*ClientOptions) (*clientOptions, error) {
	o := &clientOptions{
		OPRFBlind:     nil,
		KDFSalt:       nil,
		KSFOptions:    ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
		EnvelopeNonce: nil,
		AKENonce:      nil,
	}

	if len(options) == 0 {
		if c.oprf.blind == nil {
			return nil, ErrClientOptions.Join(internal.ErrNoOPRFBlind)
		}

		o.EnvelopeNonce = internal.RandomBytes(internal.NonceLength)

		return o, nil
	}

	// OPRF Blind.
	var err error

	if c.oprf.blind != nil && options[0].OPRFBlind != nil {
		return nil, ErrClientOptions.Join(internal.ErrDoubleOPRFBlind)
	}

	if o.OPRFBlind == nil && c.oprf.blind == nil {
		return nil, ErrClientOptions.Join(internal.ErrNoOPRFBlind)
	}

	o.OPRFBlind, err = c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
	}

	// KDF salt.
	if options[0].KDFSalt != nil {
		o.KDFSalt = options[0].KDFSalt
	}

	// KSF options.
	if err = c.clientOptionsKSFParser(o, options[0]); err != nil {
		return nil, err
	}

	// Envelope nonce.
	o.EnvelopeNonce, err = getEnvelopeNonce(options...)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return o, nil
}

func (c *Client) parseOptionsKE1(options []*ClientOptions) (*clientOptions, error) {
	o := &clientOptions{
		OPRFBlind:     nil,
		KDFSalt:       nil,
		KSFOptions:    ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
		AKENonce:      nil,
		EnvelopeNonce: nil,
	}

	if len(options) == 0 || options[0] == nil {
		c.ake.esk, o.AKENonce = makeEskAndNonce(c.conf.Group)

		return o, nil
	}

	// OPRF Blind.
	var err error

	o.OPRFBlind, err = c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
	}

	// AKE options.
	if options[0].AKE == nil {
		c.ake.esk, o.AKENonce = makeEskAndNonce(c.conf.Group)

		return o, nil
	}

	// AKE nonce.
	o.AKENonce = options[0].AKE.Nonce
	if len(o.AKENonce) == 0 {
		o.AKENonce = internal.RandomBytes(internal.NonceLength)
	}

	// Ephemeral secret key share.
	c.ake.esk, err = options[0].AKE.getSecretKeyShare(c.conf.Group)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return o, nil
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
		return ErrRegistrationResponse.Join(internal.ErrInvalidServerPublicKey, err)
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

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	// todo: is this tested against?
	if len(cr.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return errors.Join(internal.ErrCredentialResponseInvalid, internal.ErrCredentialResponseInvalidMaskedLength)
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

	if len(ke2.ServerMac) == 0 {
		return ErrKE2.Join(internal.ErrMissingMAC)
	}

	return nil
}

func (c *Client) parseOptionsKE3(options []*ClientOptions) (*clientOptions, error) {
	o := &clientOptions{
		OPRFBlind:     nil,
		KDFSalt:       nil,
		KSFOptions:    ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
		AKENonce:      nil,
		EnvelopeNonce: nil,
	}

	if len(options) == 0 || options[0] == nil {
		if c.oprf.blind == nil {
			return nil, ErrClientOptions.Join(internal.ErrNoOPRFBlind)
		}

		if c.ake.esk == nil {
			return nil, ErrClientOptions.Join(internal.ErrClientNoKeyShare)
		}

		if len(c.ake.ke1) == 0 {
			return nil, ErrClientOptions.Join(internal.ErrKE1Missing)
		}

		return o, nil
	}

	// OPRF Blind.
	var err error

	if c.oprf.blind != nil && options[0].OPRFBlind != nil {
		return nil, ErrClientOptions.Join(internal.ErrDoubleOPRFBlind)
	}

	if options[0].OPRFBlind == nil && c.oprf.blind == nil {
		return nil, ErrClientOptions.Join(internal.ErrNoOPRFBlind)
	}

	o.OPRFBlind, err = c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
	}

	// KDF salt.
	if options[0].KDFSalt != nil {
		o.KDFSalt = options[0].KDFSalt
	}

	// KSF options.
	if err = c.clientOptionsKSFParser(o, options[0]); err != nil {
		return nil, err
	}

	// KE1.
	if err = c.clientOptionsKE1Parser(options[0]); err != nil {
		return nil, err
	}

	// Ephemeral secret key share.
	c.ake.esk, err = c.parseOptionsKE3ESK(options[0].AKE)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return o, nil
}

func (c *Client) parseOptionsKE3ESK(options *AKEOptions) (*ecc.Scalar, error) {
	if c.ake.esk != nil {
		// return an error if options are present
		if options != nil && (options.SecretKeyShare != nil || len(options.SecretKeyShareSeed) != 0) {
			return nil, ErrClientOptions.Join(internal.ErrClientExistingKeyShare)
		}

		return c.ake.esk, nil
	}

	if options == nil || (options.SecretKeyShare == nil && len(options.SecretKeyShareSeed) == 0) {
		return nil, ErrClientOptions.Join(internal.ErrClientNoKeyShare)
	}

	return options.getSecretKeyShare(c.conf.Group)
}
