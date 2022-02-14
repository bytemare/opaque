// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package keyrecovery provides utility functions and structures allowing credential management.
package keyrecovery

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var errEnvelopeInvalidMac = errors.New("recover envelope: invalid envelope authentication tag")

// Credentials structure is currently used for testing purposes.
type Credentials struct {
	Idc, Ids                    []byte
	EnvelopeNonce, MaskingNonce []byte // testing: integrated to support testing
}

// Envelope represents the OPAQUE envelope.
type Envelope struct {
	Nonce   []byte
	AuthTag []byte
}

// Serialize returns the byte serialization of the envelope.
func (e *Envelope) Serialize() []byte {
	return encoding.Concat(e.Nonce, e.AuthTag)
}

func exportKey(p *internal.Parameters, randomizedPwd, nonce []byte) []byte {
	return p.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExportKey), p.KDF.Size())
}

func authTag(p *internal.Parameters, randomizedPwd, nonce, ctc []byte) []byte {
	authKey := p.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.AuthKey), p.KDF.Size())
	return p.MAC.MAC(authKey, encoding.Concat(nonce, ctc))
}

// cleartextCredentials assumes that clientPublicKey, serverPublicKey are non-nil valid group elements.
func cleartextCredentials(clientPublicKey, serverPublicKey, idc, ids []byte) []byte {
	if ids == nil {
		ids = serverPublicKey
	}

	if idc == nil {
		idc = clientPublicKey
	}

	return encoding.Concat3(serverPublicKey, encoding.EncodeVector(ids), encoding.EncodeVector(idc))
}

// Store returns the client's Envelope, the masking key for the registration, and the additional export key.
func Store(p *internal.Parameters, randomizedPwd, serverPublicKey []byte,
	creds *Credentials) (env *Envelope, pku *group.Point, export []byte) {
	// testing: integrated to support testing with set nonce
	nonce := creds.EnvelopeNonce
	if nonce == nil {
		nonce = internal.RandomBytes(p.NonceLen)
	}

	pku = getPubkey(p, randomizedPwd, nonce)

	ctc := cleartextCredentials(encoding.SerializePoint(pku, p.Group), serverPublicKey, creds.Idc, creds.Ids)
	auth := authTag(p, randomizedPwd, nonce, ctc)
	export = exportKey(p, randomizedPwd, nonce)

	env = &Envelope{
		Nonce:   nonce,
		AuthTag: auth,
	}

	return env, pku, export
}

// Recover assumes that the envelope's inner envelope has been previously checked to be of correct size.
func Recover(p *internal.Parameters, randomizedPwd, serverPublicKey, idc, ids []byte,
	envelope *Envelope) (clientSecretKey *group.Scalar, clientPublicKey *group.Point, export []byte, err error) {
	clientSecretKey, clientPublicKey = recoverKeys(p, randomizedPwd, envelope.Nonce)
	ctc := cleartextCredentials(encoding.SerializePoint(clientPublicKey, p.Group), serverPublicKey, idc, ids)

	expectedTag := authTag(p, randomizedPwd, envelope.Nonce, ctc)
	if !p.MAC.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, errEnvelopeInvalidMac
	}

	export = exportKey(p, randomizedPwd, envelope.Nonce)

	return clientSecretKey, clientPublicKey, export, nil
}
