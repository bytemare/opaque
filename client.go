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
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// ErrKe1Missing happens when GenerateKE3 is called and the client has no Ke1 in state.
	ErrKe1Missing = errors.New("client state: missing KE1 message - call GenerateKE1 first")

	errClientOptionsPrefix = errors.New("invalid client options")

	// ErrClientOptionsBlindZero indicates the OPRF blind is zero.
	ErrClientOptionsBlindZero = fmt.Errorf("%w: OPRF blind is zero", errClientOptionsPrefix)

	// ErrClientOptionsEnvelope indicates the envelope nonce is invalid.
	ErrClientOptionsEnvelope = fmt.Errorf("%w: invalid envelope", errClientOptionsPrefix)
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	Deserialize *Deserializer
	OPRF        *oprf.Client
	Ake         *ake.Client
	conf        *internal.Configuration
}

// ClientOptions enables setting internal client values to override secure defaults if otherwise not set.
type ClientOptions struct {
	OPRFBlind           *ecc.Scalar
	KSFSalt             []byte
	ServerIdentity      []byte
	EnvelopeNonce       []byte
	KDFSalt             []byte
	ClientIdentity      []byte
	KSFParameters       []int
	AKE                 AKEOptions
	EnvelopeNonceLength int
	KSFLength           int
}

type AKEOptions struct {
	EphemeralSecretKey *ecc.Scalar
	KeyShareSeed       []byte
	Nonce              []byte
	KeyShareSeedLength int
	NonceLength        int
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
func (c *Client) buildPRK(evaluation *ecc.Element, kdfSalt, ksfSalt []byte, ksfLength int) []byte {
	output := c.OPRF.Finalize(evaluation)
	stretched := c.conf.KSF.Harden(output, ksfSalt, ksfLength)

	return c.conf.KDF.Extract(kdfSalt, encoding.Concat(output, stretched))
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(
	password []byte,
	options ...ClientOptions,
) (*message.RegistrationRequest, error) {
	blind, err := c.verifyOptionBlind(options...)
	if err != nil {
		return nil, err
	}

	m := c.OPRF.Blind(password, blind)

	return &message.RegistrationRequest{
		BlindedMessage: m,
	}, nil
}

// RegistrationFinalize returns a RegistrationRecord message given the identities and the server's RegistrationResponse,
// and the export key, that the client can use for other means.
func (c *Client) RegistrationFinalize(
	resp *message.RegistrationResponse,
	options ...ClientOptions,
) (record *message.RegistrationRecord, exportKey []byte, err error) {
	o, err := c.parseOptions(options, true, false)
	if err != nil {
		return nil, nil, err
	}

	envelopeNonce, err := getEnvelopeNonce(options...)
	if err != nil {
		return nil, nil, err
	}

	randomizedPassword := c.buildPRK(resp.EvaluatedMessage, o.KDFSalt, o.KSFOptions.Salt, o.KSFOptions.Length)
	maskingKey := c.conf.KDF.Expand(randomizedPassword, []byte(tag.MaskingKey), c.conf.KDF.Size())

	envelope, clientPublicKey, exportKey := keyrecovery.Store(
		c.conf,
		randomizedPassword,
		resp.ServerPublicKey,
		o.Identities.ClientIdentity,
		o.Identities.ServerIdentity,
		envelopeNonce,
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
// invoking GenerateKE3() for the the same message but different client instances.
func (c *Client) GenerateKE1(password []byte, options ...ClientOptions) (*message.KE1, error) {
	o, err := c.parseOptions(options, false, true)
	if err != nil {
		return nil, err
	}

	m := c.OPRF.Blind(password, o.OPRFBlind)
	ke1 := c.Ake.Start(c.conf.Group, o.AKEOptions)
	ke1.CredentialRequest = message.NewCredentialRequest(m)
	c.Ake.Ke1 = ke1.Serialize()

	return ke1, nil
}

// GenerateKE3 returns a KE3 message given the server's KE2 response message and the identities. If the client or server
// identity parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) GenerateKE3(
	ke2 *message.KE2, options ...ClientOptions,
) (ke3 *message.KE3, exportKey []byte, err error) {
	if len(c.Ake.Ke1) == 0 {
		return nil, nil, ErrKe1Missing
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	o, err := c.parseOptions(options, true, false)
	if err != nil {
		return nil, nil, err
	}

	// Finalize the OPRF.
	randomizedPassword := c.buildPRK(ke2.EvaluatedMessage, o.KDFSalt, o.KSFOptions.Salt, o.KSFOptions.Length)

	// Decrypt the masked response.
	serverPublicKey, serverPublicKeyBytes,
		envelope, err := masking.Unmask(c.conf, randomizedPassword, ke2.MaskingNonce, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("unmasking: %w", err)
	}

	// Recover the client keys.
	clientSecretKey, clientPublicKey,
		exportKey, err := keyrecovery.Recover(
		c.conf,
		randomizedPassword,
		serverPublicKeyBytes,
		o.Identities.ClientIdentity,
		o.Identities.ServerIdentity,
		envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("key recovery: %w", err)
	}

	// Finalize the AKE.
	identities := o.Identities.SetIdentities(clientPublicKey, serverPublicKeyBytes)

	// If we want to be able to recover a client we need to be able to set the AKE options here
	if o.AKEOptions.EphemeralSecretKeyShare != nil {
		c.Ake.EphemeralSecretKey = o.AKEOptions.EphemeralSecretKeyShare
	}

	clientKM := ake.MakeKeyMaterial2(identities.ClientIdentity,
		nil,
		c.Ake.EphemeralSecretKey,
		clientSecretKey,
		nil)
	serverKM := ake.MakePeerKeyMaterial(identities.ServerIdentity,
		ke2.ServerPublicKeyshare,
		serverPublicKey)

	ke3, err = c.Ake.Finalize(c.conf, ke2, clientKM, serverKM)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing AKE: %w", err)
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to GenerateKE3() was successful.
func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}

type options struct {
	OPRFBlind  *ecc.Scalar
	KSFOptions *ksf.Options
	AKEOptions *ake.Options
	Identities ake.Identities
	KDFSalt    []byte
}

func (c *Client) verifyOptionBlind(clientOptions ...ClientOptions) (*ecc.Scalar, error) {
	if len(clientOptions) == 0 || clientOptions[0].OPRFBlind == nil {
		return nil, nil
	}

	if err := c.conf.OPRF.ValidateBlind(clientOptions[0].OPRFBlind); err != nil {
		return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
	}

	return clientOptions[0].OPRFBlind, nil
}

func getEnvelopeNonce(clientOptions ...ClientOptions) ([]byte, error) {
	if len(clientOptions) == 0 {
		return internal.RandomBytes(internal.NonceLength), nil
	}

	nonce := clientOptions[0].EnvelopeNonce
	nonceLength := clientOptions[0].EnvelopeNonceLength

	if err := internal.ValidateOptionsLength(nonce, nonceLength, internal.NonceLength); err != nil {
		return nil, fmt.Errorf("envelope nonce: %w", err)
	}

	if nonceLength == 0 {
		nonceLength = internal.NonceLength
	}

	if nonce == nil {
		nonce = internal.RandomBytes(nonceLength)
	}

	return nonce, nil
}

func (c *Client) parseOptions(clientOptions []ClientOptions, withKSF, withAKE bool) (*options, error) {
	o := &options{
		OPRFBlind:  nil,
		KDFSalt:    nil,
		KSFOptions: ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
		Identities: ake.Identities{},
		AKEOptions: ake.NewOptions(),
	}

	if len(clientOptions) == 0 {
		if withAKE {
			o.AKEOptions.Nonce = internal.RandomBytes(internal.NonceLength)
			o.AKEOptions.EphemeralKeyShareSeed = internal.RandomBytes(internal.NonceLength)
		}

		return o, nil
	}

	o.Identities.ClientIdentity = clientOptions[0].ClientIdentity
	o.Identities.ServerIdentity = clientOptions[0].ServerIdentity

	// OPRF Blind.
	var err error
	o.OPRFBlind, err = c.verifyOptionBlind(clientOptions...)
	if err != nil {
		return nil, err
	}

	// KDF salt.
	if clientOptions[0].KDFSalt != nil {
		o.KDFSalt = clientOptions[0].KDFSalt
	}

	// KSF options.
	if withKSF {
		if err = o.KSFOptions.Set(
			c.conf.KSF, clientOptions[0].KSFSalt, clientOptions[0].KSFParameters, clientOptions[0].KSFLength); err != nil {
			return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
		}

		if len(o.KSFOptions.Parameters) != 0 {
			c.conf.KSF.Parameterize(o.KSFOptions.Parameters...)
		}
	}

	// AKE options.
	if withAKE {
		o2 := clientOptions[0].AKE

		if err = o.AKEOptions.Set(
			o2.KeyShareSeed, o2.KeyShareSeedLength,
			o2.Nonce, o2.NonceLength); err != nil {
			return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
		}
	}

	return o, nil
}
