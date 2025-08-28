// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
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

func (s *Server) parseOptions(o *serverOptions, options []*ServerOptions) error {
	if len(options) == 0 || options[0] == nil {
		o.MaskingNonce = internal.RandomBytes(s.conf.NonceLen)
		o.SecretKeyShare = s.conf.MakeSecretKeyShare(nil)
		o.AKENonce = internal.RandomBytes(internal.NonceLength)

		return nil
	}

	// ClientOPRFKey
	if options[0].ClientOPRFKey != nil {
		if err := IsValidScalar(s.conf.OPRF.Group(), options[0].ClientOPRFKey); err != nil {
			return ErrServerOptions.Join(internal.ErrClientOPRFKey, err)
		}

		o.ClientOPRFKey = s.conf.OPRF.Group().NewScalar().Set(options[0].ClientOPRFKey)
	}

	// MaskingNonce.
	if len(options[0].MaskingNonce) != 0 {
		if len(options[0].MaskingNonce) != s.conf.NonceLen {
			return ErrServerOptions.Join(internal.ErrMaskingNonceLength)
		}

		o.MaskingNonce = make([]byte, len(options[0].MaskingNonce))
		copy(o.MaskingNonce, options[0].MaskingNonce)
	} else {
		o.MaskingNonce = internal.RandomBytes(s.conf.NonceLen)
	}

	// AKE options.
	if options[0].AKE == nil {
		o.SecretKeyShare = s.conf.MakeSecretKeyShare(nil)
		o.AKENonce = internal.RandomBytes(internal.NonceLength)

		return nil
	}

	// AKE nonce.
	if len(options[0].AKE.Nonce) == 0 {
		o.AKENonce = internal.RandomBytes(internal.NonceLength)
	} else {
		o.AKENonce = make([]byte, len(options[0].AKE.Nonce))
		copy(o.AKENonce, options[0].AKE.Nonce)
	}

	// Ephemeral secret key share.
	var err error

	o.SecretKeyShare, err = options[0].AKE.getSecretKeyShare(s.conf)
	if err != nil {
		return ErrServerOptions.Join(err)
	}

	return nil
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
		c.ake.SecretKeyShare = c.conf.MakeSecretKeyShare(nil)
		o.AKENonce = internal.RandomBytes(internal.NonceLength)

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
		c.ake.SecretKeyShare = c.conf.MakeSecretKeyShare(nil)
		o.AKENonce = internal.RandomBytes(internal.NonceLength)

		return o, nil
	}

	// AKE nonce.
	o.AKENonce = options[0].AKE.Nonce
	if len(o.AKENonce) == 0 {
		o.AKENonce = internal.RandomBytes(internal.NonceLength)
	}

	// Ephemeral secret key share.
	c.ake.SecretKeyShare, err = options[0].AKE.getSecretKeyShare(c.conf)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return o, nil
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

		if c.ake.SecretKeyShare == nil {
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
	c.ake.SecretKeyShare, err = c.parseOptionsKE3ESK(options[0].AKE)
	if err != nil {
		return nil, ErrClientOptions.Join(err)
	}

	return o, nil
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
