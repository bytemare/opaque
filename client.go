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
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// errInvalidMaskedLength happens when unmasking a masked response.
	errInvalidMaskedLength = errors.New("invalid masked response length")

	// errKe1Missing happens when GenerateKE3 is called and the client has no Ke1 in state.
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
func (c *Client) buildPRK(evaluation *ecc.Element) []byte {
	output := c.OPRF.Finalize(evaluation)
	stretched := c.conf.KSF.Harden(output, c.conf.KSFSalt, c.conf.Hash.Size())

	return c.conf.KDF.Extract(nil, encoding.Concat(output, stretched))
}

// ClientRegistrationInitOptions enables setting internal client values for the client registration.
type ClientRegistrationInitOptions struct {
	// OPRFBlind: optional
	OPRFBlind *ecc.Scalar
}

func getClientRegistrationInitBlind(options []ClientRegistrationInitOptions) *ecc.Scalar {
	if len(options) == 0 {
		return nil
	}

	return options[0].OPRFBlind
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(
	password []byte,
	options ...ClientRegistrationInitOptions,
) *message.RegistrationRequest {
	m := c.OPRF.Blind(password, getClientRegistrationInitBlind(options))

	return &message.RegistrationRequest{
		BlindedMessage: m,
	}
}

// ClientRegistrationFinalizeOptions enables setting optional client values for the client registration.
type ClientRegistrationFinalizeOptions struct {
	// ClientIdentity: optional
	ClientIdentity []byte
	// ServerIdentity: optional
	ServerIdentity []byte
	// EnvelopeNonce : optional
	EnvelopeNonce []byte
}

func initClientRegistrationFinalizeOptions(options []ClientRegistrationFinalizeOptions) *keyrecovery.Credentials {
	if len(options) == 0 {
		return &keyrecovery.Credentials{
			ClientIdentity: nil,
			ServerIdentity: nil,
			EnvelopeNonce:  nil,
		}
	}

	return &keyrecovery.Credentials{
		ClientIdentity: options[0].ClientIdentity,
		ServerIdentity: options[0].ServerIdentity,
		EnvelopeNonce:  options[0].EnvelopeNonce,
	}
}

// RegistrationFinalize returns a RegistrationRecord message given the identities and the server's RegistrationResponse.
func (c *Client) RegistrationFinalize(
	resp *message.RegistrationResponse,
	options ...ClientRegistrationFinalizeOptions,
) (record *message.RegistrationRecord, exportKey []byte) {
	credentials := initClientRegistrationFinalizeOptions(options)
	randomizedPassword := c.buildPRK(resp.EvaluatedMessage)
	maskingKey := c.conf.KDF.Expand(randomizedPassword, []byte(tag.MaskingKey), c.conf.KDF.Size())
	envelope, clientPublicKey, exportKey := keyrecovery.Store(c.conf, randomizedPassword, resp.Pks, credentials)

	return &message.RegistrationRecord{
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envelope.Serialize(),
	}, exportKey
}

// GenerateKE1Options enables setting optional values for the session, which default to secure random values if not
// set.
type GenerateKE1Options struct {
	// Blind: optional
	Blind *ecc.Scalar
	// KeyShareSeed: optional
	KeyShareSeed []byte
	// Nonce: optional
	Nonce []byte
	// NonceLength: optional
	NonceLength uint
}

func (c GenerateKE1Options) get() (*ecc.Scalar, ake.Options) {
	return c.Blind, ake.Options{
		KeyShareSeed: c.KeyShareSeed,
		Nonce:        c.Nonce,
		NonceLength:  c.NonceLength,
	}
}

func getGenerateKE1Options(options []GenerateKE1Options) (*ecc.Scalar, ake.Options) {
	if len(options) != 0 {
		return options[0].get()
	}

	return nil, ake.Options{
		KeyShareSeed: nil,
		Nonce:        nil,
		NonceLength:  internal.NonceLength,
	}
}

// GenerateKE1 initiates the authentication process, returning a KE1 message blinding the given password.
func (c *Client) GenerateKE1(password []byte, options ...GenerateKE1Options) *message.KE1 {
	blind, akeOptions := getGenerateKE1Options(options)
	m := c.OPRF.Blind(password, blind)
	ke1 := c.Ake.Start(c.conf.Group, akeOptions)
	ke1.CredentialRequest = message.NewCredentialRequest(m)
	c.Ake.Ke1 = ke1.Serialize()

	return ke1
}

// GenerateKE3Options enables setting optional client values for the client registration.
type GenerateKE3Options struct {
	// ClientIdentity: optional
	ClientIdentity []byte
	// ServerIdentity: optional
	ServerIdentity []byte
}

func initGenerateKE3Options(options []GenerateKE3Options) *ake.Identities {
	if len(options) == 0 {
		return &ake.Identities{
			ClientIdentity: nil,
			ServerIdentity: nil,
		}
	}

	return &ake.Identities{
		ClientIdentity: options[0].ClientIdentity,
		ServerIdentity: options[0].ServerIdentity,
	}
}

// GenerateKE3 returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) GenerateKE3(
	ke2 *message.KE2, options ...GenerateKE3Options,
) (ke3 *message.KE3, exportKey []byte, err error) {
	if len(c.Ake.Ke1) == 0 {
		return nil, nil, errKe1Missing
	}

	// This test is very important as it avoids buffer overflows in subsequent parsing.
	if len(ke2.MaskedResponse) != c.conf.Group.ElementLength()+c.conf.EnvelopeSize {
		return nil, nil, errInvalidMaskedLength
	}

	identities := initGenerateKE3Options(options)

	// Finalize the OPRF.
	randomizedPassword := c.buildPRK(ke2.EvaluatedMessage)

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
		identities.ClientIdentity,
		identities.ServerIdentity,
		envelope)
	if err != nil {
		return nil, nil, fmt.Errorf("key recovery: %w", err)
	}

	// Finalize the AKE.
	identities.SetIdentities(clientPublicKey, serverPublicKeyBytes)

	ke3, err = c.Ake.Finalize(c.conf, identities, clientSecretKey, serverPublicKey, ke2)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing AKE: %w", err)
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to GenerateKE3() was successful.
func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
