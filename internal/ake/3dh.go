// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

// KeyGen returns private and public keys in the group.
func KeyGen(id group.Group) (privateKey, publicKey []byte) {
	scalar := id.NewScalar().Random()
	point := id.Base().Multiply(scalar)

	return scalar.Encode(), point.Encode()
}

// Identities holds the client and server identities.
type Identities struct {
	ClientIdentity []byte
	ServerIdentity []byte
}

// SetIdentities sets the client and server identities to their respective public key if not set.
func (id *Identities) SetIdentities(clientPublicKey *group.Element, serverPublicKey []byte) *Identities {
	if id.ClientIdentity == nil {
		id.ClientIdentity = clientPublicKey.Encode()
	}

	if id.ServerIdentity == nil {
		id.ServerIdentity = serverPublicKey
	}

	return id
}

// Options enables setting optional ephemeral values, which default to secure random values if not set.
type Options struct {
	// EphemeralSecretKey: optional
	EphemeralSecretKey *group.Scalar
	// Nonce: optional
	Nonce []byte
	// NonceLength: optional
	NonceLength uint
}

func initOptions(g group.Group, options *Options) {
	/* This is currently unreachable as the callers correctly call this function with non-nil options
	if options == nil {
		options = &Options{
			EphemeralSecretKey: nil,
			Nonce:              nil,
			NonceLength:        0,
		}
	}
	*/
	if options.EphemeralSecretKey == nil {
		options.EphemeralSecretKey = g.NewScalar().Random()
	}

	if options.NonceLength == 0 {
		options.NonceLength = internal.NonceLength
	}

	if len(options.Nonce) == 0 {
		options.Nonce = internal.RandomBytes(int(options.NonceLength))
	}
}

type values struct {
	ephemeralSecretKey *group.Scalar
	nonce              []byte
}

// GetEphemeralSecretKey returns the state's ephemeral secret key.
func (v *values) GetEphemeralSecretKey() *group.Scalar {
	return v.ephemeralSecretKey
}

// GetNonce returns the secret nonce.
func (v *values) GetNonce() []byte {
	return v.nonce
}

func (v *values) flush() {
	if v.ephemeralSecretKey != nil {
		v.ephemeralSecretKey.Zero()
		v.ephemeralSecretKey = nil
	}

	v.nonce = nil
}

// setOptions sets optional values.
// There's no effect if ephemeralSecretKey and nonce have already been set in a previous call.
func (v *values) setOptions(g group.Group, options Options) *group.Element {
	initOptions(g, &options)

	if v.ephemeralSecretKey == nil ||
		(options.EphemeralSecretKey != nil && options.EphemeralSecretKey != v.ephemeralSecretKey) {
		v.ephemeralSecretKey = options.EphemeralSecretKey
	}

	if v.nonce == nil {
		v.nonce = options.Nonce
	}

	return g.Base().Multiply(v.ephemeralSecretKey)
}

func k3dh(
	p1 *group.Element,
	s1 *group.Scalar,
	p2 *group.Element,
	s2 *group.Scalar,
	p3 *group.Element,
	s3 *group.Scalar,
) []byte {
	e1 := p1.Copy().Multiply(s1).Encode()
	e2 := p2.Copy().Multiply(s2).Encode()
	e3 := p3.Copy().Multiply(s3).Encode()

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
	encodedClientID := encoding.EncodeVector(identities.ClientIdentity)
	encodedServerID := encoding.EncodeVector(identities.ServerIdentity)
	conf.Hash.Write(encoding.Concatenate([]byte(tag.VersionTag), encoding.EncodeVector(conf.Context),
		encodedClientID, ke1,
		encodedServerID, ke2.CredentialResponse.Serialize(), ke2.NonceS, ke2.EpkS.Encode()))
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (serverMacKey, clientMacKey, sessionSecret []byte) {
	prk := h.Extract(nil, ikm)
	handshakeSecret := deriveSecret(h, prk, []byte(tag.Handshake), context)
	sessionSecret = deriveSecret(h, prk, []byte(tag.SessionKey), context)
	serverMacKey = expandLabel(h, handshakeSecret, []byte(tag.MacServer), nil)
	clientMacKey = expandLabel(h, handshakeSecret, []byte(tag.MacClient), nil)

	return serverMacKey, clientMacKey, sessionSecret
}
