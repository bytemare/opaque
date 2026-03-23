// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"fmt"
	"slices"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ksf"
)

// ServerOptions override the secure default values or internally generated values.
// Only use this if you know what you're doing. Reusing seeds and nonces across sessions is a security risk,
// and breaks forward secrecy.
type ServerOptions struct {
	ClientOPRFKey *ecc.Scalar
	AKE           *AKEOptions
	MaskingNonce  []byte
}

func (s *Server) resolveServerInputs(options []*ServerOptions) (*serverInputs, error) {
	inputs := newServerInputs()

	if len(options) == 0 || options[0] == nil {
		inputs.SecretKeyShare = s.conf.MakeSecretKeyShare(nil)
		return inputs, nil
	}

	// ClientOPRFKey
	if options[0].ClientOPRFKey != nil {
		if err := IsValidScalar(s.conf.OPRF.Group(), options[0].ClientOPRFKey); err != nil {
			return nil, ErrServerOptions.Join(internal.ErrClientOPRFKey, err)
		}

		inputs.ClientOPRFKey = s.conf.OPRF.Group().NewScalar().Set(options[0].ClientOPRFKey)
	}

	// MaskingNonce.
	if len(options[0].MaskingNonce) != 0 {
		if len(options[0].MaskingNonce) != s.conf.Sizes.Nonce {
			return nil, ErrServerOptions.Join(internal.ErrMaskingNonceLength)
		}

		inputs.MaskingNonce = make([]byte, len(options[0].MaskingNonce))
		copy(inputs.MaskingNonce, options[0].MaskingNonce)
	}

	// AKE options.
	if options[0].AKE == nil {
		inputs.SecretKeyShare = s.conf.MakeSecretKeyShare(nil)
		return inputs, nil
	}

	// AKE nonce.
	if len(options[0].AKE.Nonce) != 0 {
		inputs.AKENonce = make([]byte, len(options[0].AKE.Nonce))
		copy(inputs.AKENonce, options[0].AKE.Nonce)
	}

	// Ephemeral secret key share.
	var err error

	inputs.SecretKeyShare, err = options[0].AKE.getSecretKeyShare(s.conf)
	if err != nil {
		return nil, ErrServerOptions.Join(err)
	}

	return inputs, nil
}

// ClientOptions override the secure default values or internally generated values.
// Only use this if you know what you're doing. Reusing seeds and nonces across sessions is a security risk,
// and breaks forward secrecy.
type ClientOptions struct {
	OPRFBlind *ecc.Scalar
	Password  []byte // Only used in RegistrationFinalize and GenerateKE3, for session resumption
	// without previous state, and ignored otherwise.
	AKE                 *AKEOptions
	KE1                 []byte
	KSFSalt             []byte
	EnvelopeNonce       []byte
	KDFSalt             []byte
	KSFParameters       []uint64
	EnvelopeNonceLength int
	KSFLength           int // If 0 or not set, will default to the OPRF length.
}

func (c *Client) validateOPRFBlindOption(blind *ecc.Scalar) (*ecc.Scalar, error) {
	if blind != nil {
		if err := IsValidScalar(c.conf.OPRF.Group(), blind); err != nil {
			return nil, ErrClientOptions.Join(internal.ErrInvalidOPRFBlind, err)
		}
	}

	return blind, nil
}

func resolveEnvelopeNonce(clientOptions ...*ClientOptions) ([]byte, error) {
	if len(clientOptions) == 0 { // sanity check, but never triggered since we check before calling.
		return internal.RandomBytes(internal.NonceLength), nil
	}

	nonce := clientOptions[0].EnvelopeNonce
	nonceLength := clientOptions[0].EnvelopeNonceLength

	if err := validateOptionsLength(nonce, nonceLength, internal.NonceLength); err != nil {
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

type clientInputs struct {
	Password       []byte
	OPRFBlind      *ecc.Scalar
	SecretKeyShare *ecc.Scalar
	KE1            []byte
	KSF            *ksf.Parameters
	EnvelopeNonce  []byte
	KDFSalt        []byte
	AKENonce       []byte
}

func newClientInputs(conf *internal.Configuration) *clientInputs {
	return &clientInputs{
		Password:       nil,
		OPRFBlind:      nil,
		SecretKeyShare: nil,
		KE1:            nil,
		KDFSalt:        nil,
		KSF:            ksf.NewParameters(conf.OPRF.Group().ElementLength()),
		AKENonce:       nil,
		EnvelopeNonce:  nil,
	}
}

func (c *Client) resolveKSFInputs(out *ksf.Parameters, in *ClientOptions) error {
	if err := out.Set(c.conf.KSF, in.KSFSalt, in.KSFParameters, in.KSFLength); err != nil {
		return ErrClientOptions.Join(err)
	}

	return nil
}

// resolveKE1 resolves the KE1 state from the client or options without mutating the client.
func (c *Client) resolveKE1(in *ClientOptions) ([]byte, error) {
	if len(c.ake.ke1) != 0 {
		if len(in.KE1) != 0 {
			return nil, ErrClientOptions.Join(internal.ErrDoubleKE1)
		}

		return c.ake.ke1, nil
	}

	if len(in.KE1) == 0 {
		return nil, ErrClientOptions.Join(internal.ErrKE1Missing)
	}

	// Validate that the provided KE1 message is well-formed.
	if _, err := c.Deserialize.KE1(in.KE1); err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return in.KE1, nil
}

func (c *Client) resolveFinalizeBlindCandidate(optionBlind *ecc.Scalar) (*ecc.Scalar, bool, error) {
	switch {
	case c.oprf.blind != nil && optionBlind != nil:
		return nil, false, ErrClientOptions.Join(internal.ErrDoubleOPRFBlind)
	case optionBlind != nil:
		return optionBlind, true, nil
	case c.oprf.blind == nil:
		return nil, false, ErrClientOptions.Join(internal.ErrNoOPRFBlind)
	default:
		return c.oprf.blind, false, nil
	}
}

func (c *Client) resolveFinalizePassword(optionPassword []byte) ([]byte, error) {
	switch {
	case c.oprf.password != nil && optionPassword != nil:
		return nil, ErrClientOptions.Join(internal.ErrDoublePassword)
	case optionPassword != nil:
		return slices.Clone(optionPassword), nil
	case c.oprf.password == nil:
		return nil, ErrClientOptions.Join(internal.ErrNoPassword)
	default:
		return slices.Clone(c.oprf.password), nil
	}
}

func (c *Client) resolveOPRFFinalizeInputs(inputs *clientInputs, optionBlind *ecc.Scalar, optionPassword []byte) error {
	blind, validateBlind, err := c.resolveFinalizeBlindCandidate(optionBlind)
	if err != nil {
		return err
	}

	password, err := c.resolveFinalizePassword(optionPassword)
	if err != nil {
		return err
	}

	if validateBlind {
		blind, err = c.validateOPRFBlindOption(blind)
		if err != nil {
			return err
		}
	}

	inputs.OPRFBlind = blind
	inputs.Password = password

	return nil
}

func (c *Client) resolveRegistrationFinalizeInputs(options []*ClientOptions) (*clientInputs, error) {
	inputs := newClientInputs(c.conf)

	if len(options) == 0 {
		if err := c.resolveOPRFFinalizeInputs(inputs, nil, nil); err != nil {
			return nil, err
		}

		inputs.EnvelopeNonce = internal.RandomBytes(internal.NonceLength)

		return inputs, nil
	}

	// OPRF Blind.
	if err := c.resolveOPRFFinalizeInputs(inputs, options[0].OPRFBlind, options[0].Password); err != nil {
		return nil, err
	}

	// KDF salt.
	if options[0].KDFSalt != nil {
		inputs.KDFSalt = options[0].KDFSalt
	}

	// KSF options.
	if err := c.resolveKSFInputs(inputs.KSF, options[0]); err != nil {
		return nil, err
	}

	// Envelope nonce.
	var err error

	inputs.EnvelopeNonce, err = resolveEnvelopeNonce(options...)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return inputs, nil
}

func (c *Client) resolveKE1Inputs(options []*ClientOptions) (*clientInputs, error) {
	inputs := newClientInputs(c.conf)

	if len(options) == 0 || options[0] == nil {
		c.ake.SecretKeyShare = c.conf.MakeSecretKeyShare(nil)
		inputs.AKENonce = internal.RandomBytes(internal.NonceLength)

		return inputs, nil
	}

	// OPRF Blind.
	var err error

	inputs.OPRFBlind, err = c.validateOPRFBlindOption(options[0].OPRFBlind)
	if err != nil {
		return nil, err
	}

	// AKE options.
	if options[0].AKE == nil {
		c.ake.SecretKeyShare = c.conf.MakeSecretKeyShare(nil)
		inputs.AKENonce = internal.RandomBytes(internal.NonceLength)

		return inputs, nil
	}

	// AKE nonce.
	inputs.AKENonce = options[0].AKE.Nonce
	if len(inputs.AKENonce) == 0 {
		inputs.AKENonce = internal.RandomBytes(internal.NonceLength)
	}

	// Ephemeral secret key share.
	c.ake.SecretKeyShare, err = options[0].AKE.getSecretKeyShare(c.conf)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return inputs, nil
}

func (c *Client) resolveKE3StateInputs(inputs *clientInputs) (*clientInputs, error) {
	if err := c.resolveOPRFFinalizeInputs(inputs, nil, nil); err != nil {
		return nil, err
	}

	if c.ake.SecretKeyShare == nil {
		return nil, ErrClientOptions.Join(internal.ErrClientNoKeyShare)
	}

	if len(c.ake.ke1) == 0 {
		return nil, ErrClientOptions.Join(internal.ErrKE1Missing)
	}

	inputs.SecretKeyShare = c.ake.SecretKeyShare
	inputs.KE1 = c.ake.ke1

	return inputs, nil
}

func (c *Client) resolveKE3Inputs(options []*ClientOptions) (*clientInputs, error) {
	inputs := newClientInputs(c.conf)

	if len(options) == 0 || options[0] == nil {
		return c.resolveKE3StateInputs(inputs)
	}

	// OPRF Blind.
	if err := c.resolveOPRFFinalizeInputs(inputs, options[0].OPRFBlind, options[0].Password); err != nil {
		return nil, err
	}

	// KDF salt.
	if options[0].KDFSalt != nil {
		inputs.KDFSalt = options[0].KDFSalt
	}

	// KSF options.
	if err := c.resolveKSFInputs(inputs.KSF, options[0]); err != nil {
		return nil, err
	}

	// KE1.
	var err error

	inputs.KE1, err = c.resolveKE1(options[0])
	if err != nil {
		return nil, err
	}

	// Ephemeral secret key share.
	inputs.SecretKeyShare, err = c.parseOptionsKE3ESK(options[0].AKE)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return inputs, nil
}

func (c *Client) parseOptionsKE3ESK(options *AKEOptions) (*ecc.Scalar, error) {
	if c.ake.SecretKeyShare != nil {
		// return an error if options are present
		if options != nil && (options.SecretKeyShare != nil || len(options.SecretKeyShareSeed) != 0) {
			return nil, ErrClientOptions.Join(internal.ErrClientExistingKeyShare)
		}

		return c.ake.SecretKeyShare, nil
	}

	if options == nil || (options.SecretKeyShare == nil && len(options.SecretKeyShareSeed) == 0) {
		return nil, ErrClientOptions.Join(internal.ErrClientNoKeyShare)
	}

	return options.getSecretKeyShare(c.conf)
}

// validateOptionsLength returns an error if the input slice does not match the provided length (if != 0) or is shorter
// than the reference length.
func validateOptionsLength(input []byte, length int, referenceLength uint32) error {
	if input == nil {
		return nil
	}

	if length < 0 {
		return internal.ErrProvidedLengthNegative
	}

	// If the length is 0, it means the required length is not overridden, and the input slice must be at least the
	// reference length.
	if length == 0 {
		if len(input) < int(referenceLength) {
			return fmt.Errorf("%w: want %d, got %d", internal.ErrSliceShorterLength, referenceLength, len(input))
		}

		return nil
	}

	// If a length is provided, the input slice must match it.
	if length != len(input) {
		return fmt.Errorf("%w: want %d, got %d", internal.ErrSliceDifferentLength, length, len(input))
	}

	return nil
}
