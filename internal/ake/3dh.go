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
	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

// KeyGen returns private and public keys in the ecc.
func KeyGen(g ecc.Group, seed []byte) (*ecc.Scalar, *ecc.Element) {
	if len(seed) == 0 {
		seed = internal.RandomBytes(internal.SeedLength)
	}

	return oprf.IDFromGroup(g).DeriveKeyPair(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
}

func diffieHellman(s *ecc.Scalar, e *ecc.Element) *ecc.Element {
	/*
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
func SetIdentities(clientID []byte, clientPublicKey *ecc.Element, serverID, serverPublicKey []byte) *Identities {
	id := &Identities{
		ClientIdentity: clientID,
		ServerIdentity: serverID,
	}

	if id.ClientIdentity == nil {
		id.ClientIdentity = clientPublicKey.Encode()
	}

	if id.ServerIdentity == nil {
		id.ServerIdentity = serverPublicKey
	}

	return id
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
	conf *internal.Configuration, identities *Identities, ikm, ke1 []byte, ke2 *message.KE2,
) (sessionSecret, macS, macC []byte) {
	h := conf.NewHash()
	preamble := initTranscript(h, identities, conf.Context, ke1, ke2)
	serverMacKey, clientMacKey, sessionSecret := deriveKeys(conf.KDF, ikm, preamble)
	serverMac := conf.MAC.MAC(serverMacKey, preamble)
	h.Write(serverMac)
	transcript3 := h.Sum()

	clientMac := conf.MAC.MAC(clientMacKey, transcript3)

	return sessionSecret, serverMac, clientMac
}

func buildLabel(length int, label, context []byte) []byte {
	return encoding.Concat3(
		encoding.I2OSP(length, 2),
		encoding.EncodeVectorLen(append([]byte(tag.LabelPrefix), label...), 1),
		encoding.EncodeVectorLen(context, 1))
}

func expandLabel(h *internal.KDF, secret, label, context []byte) []byte {
	hkdfLabel := buildLabel(h.Size(), label, context)
	return h.Expand(secret, hkdfLabel, h.Size())
}

func deriveSecret(h *internal.KDF, secret, label, context []byte) []byte {
	return expandLabel(h, secret, label, context)
}

// initTranscript initializes the transcript by adding the following values to the running hash state in h and returns
// the current hash output:
// Version || Context || ClientIdentity || KE1 || ServerIdentity || CredentialResponse || ServerNonce || ServerKeyShare.
func initTranscript(h *internal.Hash, identities *Identities, context, ke1 []byte, ke2 *message.KE2) []byte {
	h.Write([]byte(tag.VersionTag))
	h.Write(encoding.EncodeVector(context))
	h.Write(encoding.EncodeVector(identities.ClientIdentity))
	h.Write(ke1)
	h.Write(encoding.EncodeVector(identities.ServerIdentity))
	h.Write(ke2.CredentialResponse.Serialize())
	h.Write(ke2.ServerNonce)
	h.Write(ke2.ServerKeyShare.Encode())

	return h.Sum()
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (serverMacKey, clientMacKey, sessionSecret []byte) {
	prk := h.Extract(nil, ikm)
	sessionSecret = deriveSecret(h, prk, []byte(tag.SessionKey), context)
	handshakeSecret := deriveSecret(h, prk, []byte(tag.Handshake), context)
	serverMacKey = deriveSecret(h, handshakeSecret, []byte(tag.MacServer), nil)
	clientMacKey = deriveSecret(h, handshakeSecret, []byte(tag.MacClient), nil)

	return serverMacKey, clientMacKey, sessionSecret
}
