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
	"fmt"
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

var (
	errClientOptionsPrefix = errors.New("invalid client options")

	// ErrClientOptionsBlindZero indicates the OPRF blind is zero.
	ErrClientOptionsBlindZero = fmt.Errorf("%w: OPRF blind is zero", errClientOptionsPrefix)

	// ErrClientOptionsEnvelope indicates the envelope nonce is invalid.
	ErrClientOptionsEnvelope = fmt.Errorf("%w: invalid envelope", errClientOptionsPrefix)
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
	secretKey   *ecc.Scalar // The long-term secret key, if recovered.
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
		secretKey: nil,
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
// Optionally, that value can be overridden by providing a ClientOptions with a OPRF Blind value, but at your own risks.
func (c *Client) RegistrationInit(
	password []byte,
	options ...*ClientOptions,
) (*message.RegistrationRequest, error) {
	// todo: blind must not already be set + options
	blind, err := c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
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
	if c.ake.esk != nil {
		return nil, ErrClientPreExistingKeyShare
	}

	o, err := c.parseOptionsKE1(options)
	if err != nil {
		return nil, err
	}

	var m *ecc.Element
	c.oprf.blind, m = c.conf.OPRF.Blind(password, o.OPRFBlind)
	c.oprf.password = password
	ke1 := ake.Start(c.conf.Group, c.ake.esk, o.AKENonce)
	ke1.CredentialRequest = message.NewCredentialRequest(m)
	c.ake.ke1 = ke1.Serialize()

	return ke1, nil
}

func (c *Client) validateKE2(ke2 *message.KE2) error {
	if ke2 == nil {
		return fmt.Errorf("%w: KE2 message is nil", errClientOptionsPrefix)
	}

	if ke2.CredentialResponse == nil || ke2.CredentialResponse.EvaluatedMessage == nil {
		return fmt.Errorf("%w: KE2 message is missing evaluated message", errClientOptionsPrefix)
	}

	if err := IsValidElement(c.conf.Group, ke2.CredentialResponse.EvaluatedMessage); err != nil {
		return fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
	}

	if ke2.ServerPublicKeyshare == nil {
		return fmt.Errorf("%w: KE2 message is missing server public key share", errClientOptionsPrefix)
	}

	if err := IsValidElement(c.conf.Group, ke2.ServerPublicKeyshare); err != nil {
		return fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return ErrInvalidMaskedLength
	}

	return nil
}

// GenerateKE3 returns a KE3 message given the server's KE2 response message and the identities. If the client or server
// identity parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) GenerateKE3(
	ke2 *message.KE2,
	clientIdentity, serverIdentity []byte,
	options ...*ClientOptions,
) (ke3 *message.KE3, sessionKey, exportKey []byte, err error) {
	if err := c.validateKE2(ke2); err != nil {
		return nil, nil, nil, err
	}

	o, err := c.parseOptionsKE3(options)
	if err != nil {
		return nil, nil, nil, err
	}

	// Finalize the OPRF.
	randomizedPassword := c.buildPRK(ke2.EvaluatedMessage, o.KDFSalt, o.KSFOptions.Salt, o.KSFOptions.Length)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.conf, randomizedPassword, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to unmask KE2: %w", err)
	}

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
		return nil, nil, nil, fmt.Errorf("failed to recover client key: %w", err)
	}

	// Finalize the AKE.
	identities := (&ake.Identities{
		ClientIdentity: clientIdentity,
		ServerIdentity: serverIdentity,
	}).SetIdentities(clientPublicKey, serverPublicKeyBytes)

	c.secretKey = clientSecretKey
	km := ake.KeyMaterial{
		EphemeralSecretKey: c.ake.esk,
		SecretKey:          c.secretKey,
	}

	ke3, sessionKey, macOK := ake.Finalize(c.conf, &km, identities, serverPublicKey, ke2, c.ake.ke1)
	if !macOK {
		return nil, nil, nil, ErrClientAkeFailedHandshakeServerMac
	}

	return ke3, sessionKey, exportKey, nil
}

// EphemeralSecretKeyShare returns the client's ephemeral session secret key share, if it has been set in GenerateKE2.
func (c *Client) EphemeralSecretKeyShare() *ecc.Scalar {
	return c.ake.esk
}

// SecretKey returns the client's long-term secret key, if it has been recovered in GenerateKE2.
func (c *Client) SecretKey() *ecc.Scalar {
	return c.secretKey
}

// Flush attempts to zero out the ephemeral and secret keys, and sets them to nil.
func (c *Client) Flush() {
	if c.ake.esk != nil {
		c.ake.esk.Random()
		c.ake.esk.Zero()
		c.ake.esk = nil
	}

	if c.secretKey != nil {
		c.secretKey.Random()
		c.secretKey.Zero()
		c.secretKey = nil
	}

	if c.oprf.blind != nil {
		c.oprf.blind.Random()
		c.oprf.blind.Zero()
		c.oprf.blind = nil
	}

	if len(c.oprf.password) > 0 {
		for i := range c.oprf.password {
			c.oprf.password[i] = 0
		}
		c.oprf.password = nil
	}

}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *ecc.Element, kdfSalt, ksfSalt []byte, ksfLength int) []byte {
	output := c.conf.OPRF.Finalize(c.oprf.blind, c.oprf.password, evaluation)
	stretched := c.conf.KSF.Harden(output, ksfSalt, ksfLength)

	return c.conf.KDF.Extract(kdfSalt, encoding.Concat(output, stretched))
}

func (c *Client) verifyOptionBlind(clientOptions ...*ClientOptions) (*ecc.Scalar, error) {
	if len(clientOptions) == 0 || clientOptions[0].OPRFBlind == nil {
		return nil, nil
	}

	if err := IsValidScalar(c.conf.OPRF.Group(), clientOptions[0].OPRFBlind); err != nil {
		return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
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
		return nil, fmt.Errorf("%w: failed to verify envelope nonce parameters: %w", errClientOptionsPrefix, err)
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
		return fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
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
			return fmt.Errorf("%w: KE1 already in state but provided in options", errClientOptionsPrefix)
		}

		return nil
	}

	if len(in.KE1) == 0 {
		return fmt.Errorf("%w: KE1 is missing in state and not provided", errClientOptionsPrefix)
	}

	if _, err := c.Deserialize.KE1(in.KE1); err != nil {
		return fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
	}

	c.ake.ke1 = in.KE1

	return nil
}

/*
func (c *Client) parseOptions(options []*ClientOptions, witEnvNonce, withKSF, withKE1 bool) (*clientOptions, error) {
	o := &clientOptions{
		OPRFBlind:  nil,
		KDFSalt:    nil,
		KSFOptions: ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
	}

	if len(options) == 0 {

		slog.Info("on registration, we actually don't need ake options and generate them internally")
		esk, nonce, err := processAkeOptions(c.conf.Group, nil)
		if err != nil {
			return nil, err
		}

		c.ake.esk = esk
		o.AKENonce = nonce

		return o, nil
	}

	// OPRF Blind.
	var err error
	o.OPRFBlind, err = c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
	}

	// KDF salt.
	if options[0].KDFSalt != nil {
		o.KDFSalt = options[0].KDFSalt
	}

	// AKE options.
	esk, nonce, err := processAkeOptions(c.conf.Group, options[0].AKE)
	if err != nil {
		return nil, err
	}

	c.ake.esk = esk
	o.AKENonce = nonce

	if options[0].AKE != nil &&
		options[0].AKE.EphemeralSecretKeyShare != nil &&
		c.ake.esk != nil {
		return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, ErrClientExistingKeyShare)
	}

	// Envelope nonce.
	if witEnvNonce {
		o.EnvelopeNonce, err = getEnvelopeNonce(options...)
		if err != nil {
			return nil, err
		}
	}

	// KSF options.
	if withKSF {
		if err = c.clientOptionsKSFParser(o, options[0]); err != nil {
			return nil, err
		}
	}

	// KE1 options.
	if withKE1 {
		if err = c.clientOptionsKE1Parser(options[0]); err != nil {
			return nil, err
		}
	}

	return o, nil
}
*/

func (c *Client) parseOptionsRegistrationFinalize(options []*ClientOptions) (*clientOptions, error) {
	// blind, kdf, ksf, envelope nonce

	o := &clientOptions{
		OPRFBlind:  nil,
		KDFSalt:    nil,
		KSFOptions: ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
	}

	if len(options) == 0 {
		if c.oprf.blind == nil {
			return nil, fmt.Errorf("%w: OPRF blind is missing", errClientOptionsPrefix)
		}

		o.EnvelopeNonce = internal.RandomBytes(internal.NonceLength)

		return o, nil
	}

	// OPRF Blind.
	var err error

	if c.oprf.blind != nil && options[0].OPRFBlind != nil {
		return nil, fmt.Errorf("%w: %s", errClientOptionsPrefix, "OPRF blind is already set in state")
	}

	if o.OPRFBlind == nil && c.oprf.blind == nil {
		return nil, fmt.Errorf("%w: OPRF blind is missing", errClientOptionsPrefix)
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
		return nil, err
	}

	return o, nil
}

func (c *Client) parseOptionsKE1(options []*ClientOptions) (*clientOptions, error) {
	// blind, esk, ake nonce

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
	c.ake.esk, err = options[0].AKE.getEphemeralSecretKeyShare(c.conf.Group)
	if err != nil {
		return nil, err
	}

	return o, nil
}

func (c *Client) parseOptionsKE3(options []*ClientOptions) (*clientOptions, error) {
	// blind, ke1, kdf, ksf, ke1, esk
	o := &clientOptions{
		OPRFBlind:     nil,
		KDFSalt:       nil,
		KSFOptions:    ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
		AKENonce:      nil,
		EnvelopeNonce: nil,
	}

	if len(options) == 0 || options[0] == nil {
		if c.oprf.blind == nil {
			return nil, fmt.Errorf("%w: OPRF blind is missing", errClientOptionsPrefix)
		}

		if c.ake.esk == nil {
			return nil, ErrClientNoKeyShare
		}

		if len(c.ake.ke1) == 0 {
			return nil, fmt.Errorf("%w: KE1 message is missing", errClientOptionsPrefix)
		}

		return o, nil
	}

	// OPRF Blind.
	var err error
	if c.oprf.blind != nil && options[0].OPRFBlind != nil {
		return nil, fmt.Errorf("%w: %s", errClientOptionsPrefix, "OPRF blind is already set in state")
	}

	if o.OPRFBlind == nil && c.oprf.blind == nil {
		return nil, fmt.Errorf("%w: OPRF blind is missing", errClientOptionsPrefix)
	}

	o.OPRFBlind, err = c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
	}

	//if o.OPRFBlind == nil && c.oprf.blind == nil {
	//	return nil, fmt.Errorf("%w: OPRF blind is missing", errClientOptionsPrefix)
	//}

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
		return nil, err
	}

	return o, nil
}

func (c *Client) parseOptionsKE3ESK(options *AKEOptions) (*ecc.Scalar, error) {
	if c.ake.esk != nil {
		// return an error if options are present
		if options != nil && (options.EphemeralSecretKeyShare != nil || len(options.SecretKeyShareSeed) != 0) {
			return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, ErrClientExistingKeyShare)
		}

		return c.ake.esk, nil
	}

	if options == nil || (options.EphemeralSecretKeyShare == nil && len(options.SecretKeyShareSeed) == 0) {
		return nil, ErrClientNoKeyShare
	}

	return options.getEphemeralSecretKeyShare(c.conf.Group)
}
