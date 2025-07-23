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

var (
	// ErrOptionsSeed indicates the AKE key share seed is invalid.
	ErrOptionsSeed = fmt.Errorf("invalid AKE key share seed")

	// ErrOptionsNonce indicates the AKE nonce is not valid.
	ErrOptionsNonce = fmt.Errorf("invalid AKE nonce")
)

// KeyGen returns private and public keys in the ecc.
func KeyGen(id ecc.Group) (privateKey, publicKey []byte) {
	scalar := id.NewScalar().Random()
	point := id.Base().Multiply(scalar)

	return scalar.Encode(), point.Encode()
}

func diffieHellman(s *ecc.Scalar, e *ecc.Element) *ecc.Element {
	/*
		if id == ecc.Ristretto255Sha512 || id == ecc.P256Sha256 {
			e.Copy().Multiply(s)
		}

		if id == ecc.Curve25519 {
			// TODO
		}
	*/
	return e.Copy().Multiply(s)
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
		EphemeralKeyShareSeed:       nil,
		Nonce:                       nil,
		EphemeralKeyShareSeedLength: internal.SeedLength,
		NonceLength:                 internal.NonceLength,
	}
}

func (o *Options) Set(seed []byte, seedLength int, nonce []byte, nonceLength int) error {
	if err := setOptions(&o.EphemeralKeyShareSeed, &o.EphemeralKeyShareSeedLength,
		seed, seedLength, internal.SeedLength, ErrOptionsSeed); err != nil {
		return err
	}

	if err := setOptions(&o.Nonce, &o.NonceLength,
		nonce, nonceLength, internal.NonceLength, ErrOptionsNonce); err != nil {
		return err
	}

	return nil
}

func setOptions(s *[]byte, l *uint32, input []byte, length int, referenceLength uint32, refErr error) error {
	if err := internal.ValidateOptionsLength(input, length, referenceLength); err != nil {
		return fmt.Errorf("%w: %w", refErr, err)
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

func MakeKeyShare(g ecc.Group, seed []byte, ephemeralSecretKey *ecc.Scalar) (*ecc.Scalar, *ecc.Element) {
	if ephemeralSecretKey == nil {
		ephemeralSecretKey = oprf.IDFromGroup(g).
			DeriveKey(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
	}

	return ephemeralSecretKey, g.Base().Multiply(ephemeralSecretKey)
}

func k3dh(
	p1 *ecc.Element,
	s1 *ecc.Scalar,
	p2 *ecc.Element,
	s2 *ecc.Scalar,
	p3 *ecc.Element,
	s3 *ecc.Scalar,
) []byte {
	e1 := diffieHellman(s1, p1).Encode()
	e2 := diffieHellman(s2, p2).Encode()
	e3 := diffieHellman(s3, p3).Encode()

	return encoding.Concat3(e1, e2, e3)
}

func core3DH(
	conf *internal.Configuration, idC, idS, ikm, ke1 []byte, ke2 *message.KE2,
) (sessionSecret, macS, macC []byte) {
	initTranscript(conf, idC, idS, ke1, ke2)

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

func initTranscript(conf *internal.Configuration, idC, idS, ke1 []byte, ke2 *message.KE2) {
	encodedClientID := encoding.EncodeVector(idC)
	encodedServerID := encoding.EncodeVector(idS)
	conf.Hash.Write(encoding.Concatenate([]byte(tag.VersionTag), encoding.EncodeVector(conf.Context),
		encodedClientID, ke1,
		encodedServerID, ke2.CredentialResponse.Serialize(), ke2.ServerNonce, ke2.ServerPublicKeyshare.Encode()))
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (serverMacKey, clientMacKey, sessionSecret []byte) {
	prk := h.Extract(nil, ikm)
	handshakeSecret := deriveSecret(h, prk, []byte(tag.Handshake), context)
	sessionSecret = deriveSecret(h, prk, []byte(tag.SessionKey), context)
	serverMacKey = expandLabel(h, handshakeSecret, []byte(tag.MacServer), nil)
	clientMacKey = expandLabel(h, handshakeSecret, []byte(tag.MacClient), nil)

	return serverMacKey, clientMacKey, sessionSecret
}
