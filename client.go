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
	errClientOptionsPrefix = errors.New("invalid client options")

	// ErrClientOptionsBlindZero indicates the OPRF blind is zero.
	ErrClientOptionsBlindZero = fmt.Errorf("%w: OPRF blind is zero", errClientOptionsPrefix)

	// ErrClientOptionsEnvelope indicates the envelope nonce is invalid.
	ErrClientOptionsEnvelope = fmt.Errorf("%w: invalid envelope", errClientOptionsPrefix)
)

// Client represents an OPAQUE Client, exposing its functions and holding its state.
// The state includes the OPRF blind, during a registration or authentication session, and the ephemeral secret key
// share during an authentication session.
type Client struct {
	Deserialize *Deserializer
	OPRF        *oprf.Client
	conf        *internal.Configuration
	ake         ake.KeyMaterial
	ke1         []byte
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
		Deserialize: &Deserializer{conf: conf},
		conf:        conf,
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
	clientIdentity, serverIdentity []byte,
	options ...*ClientOptions,
) (record *message.RegistrationRecord, exportKey []byte, err error) {
	o, err := c.parseOptions(options, true, true, false)
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
		clientIdentity,
		serverIdentity,
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
func (c *Client) GenerateKE1(password []byte, options ...*ClientOptions) (*message.KE1, error) {
	if c.ake.EphemeralSecretKey != nil {
		return nil, fmt.Errorf("an AKE secret key share exists in the client state, indicating a prior run." +
			"Flush the Client state before starting a new run of the protocol")
	}

	o, err := c.parseOptions(options, false, false, false)
	if err != nil {
		return nil, err
	}

	m := c.OPRF.Blind(password, o.OPRFBlind)
	var ke1 *message.KE1
	ke1, c.ake.EphemeralSecretKey = ake.Start(c.conf.Group, o.AKEOptions)
	ke1.CredentialRequest = message.NewCredentialRequest(m)
	c.ke1 = ke1.Serialize()

	return ke1, nil
}

// GenerateKE3 returns a KE3 message given the server's KE2 response message and the identities. If the client or server
// identity parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) GenerateKE3(
	ke2 *message.KE2,
	clientIdentity, serverIdentity []byte,
	options ...*ClientOptions,
) (ke3 *message.KE3, sessionKey, exportKey []byte, err error) {
	if len(c.ke1) == 0 {
		return nil, nil, nil, ErrKe1Missing
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return nil, nil, nil, ErrInvalidMaskedLength
	}

	o, err := c.parseOptions(options, false, true, true)
	if err != nil {
		return nil, nil, nil, err
	}

	if err = c.ke2SetEphemeralKeyShare(o.AKEOptions); err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
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

	c.ake.SecretKey = clientSecretKey

	ke3, sessionKey, macOK := ake.Finalize(c.conf, &c.ake, identities, serverPublicKey, ke2, c.ke1)
	if !macOK {
		return nil, nil, nil, ErrClientAkeFailedHandshakeServerMac
	}

	return ke3, sessionKey, exportKey, nil
}

// EphemeralSecretKeyShare returns the client's ephemeral session secret key share, if it has been set in GenerateKE2.
func (c *Client) EphemeralSecretKeyShare() *ecc.Scalar {
	return c.ake.EphemeralSecretKey
}

// SecretKey returns the client's long-term secret key, if it has been recovered in GenerateKE2.
func (c *Client) SecretKey() *ecc.Scalar {
	return c.ake.SecretKey
}

// Flush attempts to zero out the ephemeral and secret keys, and sets them to nil.
func (c *Client) Flush() {
	c.ake.Flush()
}

// buildPRK derives the randomized password from the OPRF output.
func (c *Client) buildPRK(evaluation *ecc.Element, kdfSalt, ksfSalt []byte, ksfLength int) []byte {
	output := c.OPRF.Finalize(evaluation)
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
	AKEOptions    *ake.Options
	Identities    ake.Identities
	EnvelopeNonce []byte
	KDFSalt       []byte
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

func (c *Client) clientOptionsKE1Parser(in *ClientOptions) error {
	if len(c.ke1) == 0 && len(in.KE1) == 0 {
		return fmt.Errorf("%w: KE1 is missing in state and not provided", errClientOptionsPrefix)
	}

	if len(c.ke1) != 0 && len(in.KE1) == 0 {
		return nil
	}

	if _, err := c.Deserialize.KE1(in.KE1); err != nil {
		return fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
	}

	c.ke1 = in.KE1
	return nil
}

func (c *Client) ke2SetEphemeralKeyShare(options *ake.Options) error {
	if (c.ake.EphemeralSecretKey == nil) && (options.EphemeralSecretKeyShare == nil) {
		return fmt.Errorf("no ephemeral secret key share set in the options or in the client state")
	}

	if (c.ake.EphemeralSecretKey != nil) && (options.EphemeralSecretKeyShare != nil) {
		if !c.ake.EphemeralSecretKey.Equal(options.EphemeralSecretKeyShare) {
			return fmt.Errorf("an AKE secret key share exists in the client state, but a different one" +
				"was provided in the options. Only one must be set")
		}
	}

	if options.EphemeralSecretKeyShare != nil {
		// Here, a new ephemeral secret key share is set in the options, and the client state is empty. So we set the key
		// share up. // todo: verify whether this key is compatible with the public key set in KE1.
		c.ake.EphemeralSecretKey = options.EphemeralSecretKeyShare
	}

	return nil
}

func (c *Client) parseOptions(options []*ClientOptions, withNonce, withKSF, withKE1 bool) (*clientOptions, error) {
	o := &clientOptions{
		OPRFBlind:  nil,
		KDFSalt:    nil,
		KSFOptions: ksf.NewOptions(c.conf.OPRF.Group().ElementLength()),
		AKEOptions: ake.NewOptions(),
	}

	if len(options) == 0 {
		if err := processAkeOptions(c.conf.Group, o.AKEOptions, nil); err != nil {
			return nil, err
		}

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
	if err = processAkeOptions(c.conf.Group, o.AKEOptions, options[0].AKE); err != nil {
		return nil, err
	}

	if options[0].AKE != nil {
		if options[0].AKE.EphemeralSecretKeyShare != nil {
			if c.ake.EphemeralSecretKey != nil {
				return nil, fmt.Errorf("%w: an AKE secret key share was provided in the client options,"+
					"but the client already has an existing secret key share registered in its state", errClientOptionsPrefix)
			}
		}
	}

	// Envelope nonce.
	if withNonce {
		o.EnvelopeNonce, err = getEnvelopeNonce(options...)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
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
