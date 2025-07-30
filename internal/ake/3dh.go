// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

// KeyGen returns private and public keys in the ecc.
func KeyGen(g ecc.Group, seed ...[]byte) (*ecc.Scalar, *ecc.Element) {
	var s []byte
	if len(seed) != 0 && len(seed[0]) > 0 {
		s = seed[0]
	} else {
		s = internal.RandomBytes(internal.SeedLength)
	}

	sk := oprf.IDFromGroup(g).DeriveKey(s, []byte(tag.DeriveDiffieHellmanKeyPair))

	return sk, g.Base().Multiply(sk)
}

func diffieHellman(s *ecc.Scalar, e *ecc.Element) *ecc.Element {
	/*
		if id == ecc.Curve25519 {
			// TODO
		}
	*/
	return e.Copy().Multiply(s)
}

// KeyMaterial holds the ephemeral and secret keys used in the 3DH protocol.
type KeyMaterial struct {
	EphemeralSecretKey *ecc.Scalar
	SecretKey          *ecc.Scalar
}

// Flush attempts to zero out the ephemeral and secret keys, and sets them to nil.
func (m *KeyMaterial) Flush() {
	m.EphemeralSecretKey.Zero()
	m.EphemeralSecretKey = nil
	m.SecretKey.Zero()
	m.SecretKey = nil
}

// Identities holds the client and server identities.
type Identities struct {
	ClientIdentity []byte
	ServerIdentity []byte
}

// SetIdentities sets the client and server identities to their respective public key if not set.
func (id *Identities) SetIdentities(clientPublicKey *ecc.Element, serverPublicKey []byte) *Identities {
	if id.ClientIdentity == nil {
		id.ClientIdentity = clientPublicKey.Encode()
	}

	if id.ServerIdentity == nil {
		id.ServerIdentity = serverPublicKey
	}

	return id
}

// Options enable setting optional ephemeral values, which default to secure random values if not set.
type Options struct {
	EphemeralSecretKeyShare     *ecc.Scalar
	EphemeralKeyShareSeed       []byte
	Nonce                       []byte
	EphemeralKeyShareSeedLength uint32
	NonceLength                 uint32
}

// NewOptions returns a new Options structure with default values.
func NewOptions() *Options {
	return &Options{
		EphemeralSecretKeyShare:     nil,
		EphemeralKeyShareSeed:       nil,
		Nonce:                       nil,
		EphemeralKeyShareSeedLength: internal.SeedLength,
		NonceLength:                 internal.NonceLength,
	}
}

// Set sets the ephemeral key share seed and nonce given the provided values, or generates secure random values
// if not provided.
func (o *Options) Set(seed []byte, seedLength int, nonce []byte, nonceLength int) error {
	if err := setOptions(&o.EphemeralKeyShareSeed, &o.EphemeralKeyShareSeedLength,
		seed, seedLength, internal.SeedLength); err != nil {
		return fmt.Errorf("invalid AKE key share seed: %w", err)
	}

	if err := setOptions(&o.Nonce, &o.NonceLength,
		nonce, nonceLength, internal.NonceLength); err != nil {
		return fmt.Errorf("invalid AKE nonce: %w", err)
	}

	return nil
}

// GetEphemeralKeyShare returns the ephemeral secret key share and its corresponding public key share.
func (o *Options) GetEphemeralKeyShare(g ecc.Group) (*ecc.Scalar, *ecc.Element) {
	esk := o.EphemeralSecretKeyShare
	if esk == nil {
		esk = oprf.IDFromGroup(g).
			DeriveKey(o.EphemeralKeyShareSeed, []byte(tag.DeriveDiffieHellmanKeyPair))
	}

	return esk, g.Base().Multiply(esk)
}

func setOptions(s *[]byte, l *uint32, input []byte, length int, referenceLength uint32) error {
	if err := internal.ValidateOptionsLength(input, length, referenceLength); err != nil {
		return err
	}

	if length != 0 {
		*l = uint32(length)
	}

	if len(input) == 0 {
		*s = internal.RandomBytes(int(*l))
	} else {
		*s = input
	}

	return nil
}

func k3dh(
	p1 *ecc.Element,
	s1 *ecc.Scalar,
	p2 *ecc.Element,
	s2 *ecc.Scalar,
	p3 *ecc.Element,
	s3 *ecc.Scalar,
) []byte {
	// slog.Info("3DH", "p1", p1.Hex(), "s1", s1.Hex(), "p2", p2.Hex(), "s2", s2.Hex(), "p3", p3.Hex(), "s3", s3.Hex())

	e1 := diffieHellman(s1, p1).Encode()
	e2 := diffieHellman(s2, p2).Encode()
	e3 := diffieHellman(s3, p3).Encode()

	return encoding.Concat3(e1, e2, e3)
}

func core3DH(
	conf *internal.Configuration, identities *Identities, ikm, ke1 []byte, ke2 *message.KE2,
) (sessionSecret, macS, macC []byte) {
	initTranscript(conf, identities, ke1, ke2)

	serverMacKey, clientMacKey, sessionSecret := deriveKeys(conf.KDF, ikm, conf.Hash.Sum()) // preamble
	serverMac := conf.MAC.MAC(serverMacKey, conf.Hash.Sum())                                // transcript2
	conf.Hash.Write(serverMac)
	transcript3 := conf.Hash.Sum()
	clientMac := conf.MAC.MAC(clientMacKey, transcript3)

	return sessionSecret, serverMac, clientMac
}

func buildLabel(length int, label, context []byte) []byte {
	return encoding.Concat3(
		encoding.I2OSP(length, 2),
		encoding.EncodeVectorLen(append([]byte(tag.LabelPrefix), label...), 1),
		encoding.EncodeVectorLen(context, 1))
}

func expand(h *internal.KDF, secret, hkdfLabel []byte) []byte {
	return h.Expand(secret, hkdfLabel, h.Size())
}

func expandLabel(h *internal.KDF, secret, label, context []byte) []byte {
	hkdfLabel := buildLabel(h.Size(), label, context)
	return expand(h, secret, hkdfLabel)
}

func deriveSecret(h *internal.KDF, secret, label, context []byte) []byte {
	return expandLabel(h, secret, label, context)
}

func initTranscript(conf *internal.Configuration, identities *Identities, ke1 []byte, ke2 *message.KE2) {
	addToHash(conf, []byte(tag.VersionTag),
		encoding.EncodeVector(conf.Context),
		encoding.EncodeVector(identities.ClientIdentity),
		ke1,
		encoding.EncodeVector(identities.ServerIdentity),
		ke2.CredentialResponse.Serialize(),
		ke2.ServerNonce,
		ke2.ServerPublicKeyshare.Encode(),
	)
}

func addToHash(conf *internal.Configuration, data ...[]byte) {
	for _, d := range data {
		conf.Hash.Write(d)
	}
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (serverMacKey, clientMacKey, sessionSecret []byte) {
	prk := h.Extract(nil, ikm)
	handshakeSecret := deriveSecret(h, prk, []byte(tag.Handshake), context)
	sessionSecret = deriveSecret(h, prk, []byte(tag.SessionKey), context)
	serverMacKey = expandLabel(h, handshakeSecret, []byte(tag.MacServer), nil)
	clientMacKey = expandLabel(h, handshakeSecret, []byte(tag.MacClient), nil)

	return serverMacKey, clientMacKey, sessionSecret
}
