// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package keyrecovery provides utility functions and structures allowing credential management.
package keyrecovery

import (
	"errors"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var errEnvelopeInvalidMac = errors.New("invalid envelope authentication tag")

// Credentials structure is currently used for testing purposes.
type Credentials struct {
	ClientIdentity, ServerIdentity []byte
	EnvelopeNonce                  []byte // testing: integrated to support testing
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

func exportKey(conf *internal.Configuration, randomizedPwd, nonce []byte) []byte {
	return conf.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExportKey), conf.KDF.Size())
}

func authTag(conf *internal.Configuration, randomizedPwd, nonce, ctc []byte) []byte {
	authKey := conf.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.AuthKey), conf.KDF.Size())
	return conf.MAC.MAC(authKey, encoding.Concat(nonce, ctc))
}

// cleartextCredentials assumes that clientPublicKey, serverPublicKey are non-nil valid group elements.
func cleartextCredentials(clientPublicKey, serverPublicKey, clientIdentity, serverIdentity []byte) []byte {
	if clientIdentity == nil {
		clientIdentity = clientPublicKey
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKey
	}

	return encoding.Concat3(
		serverPublicKey,
		encoding.EncodeVector(serverIdentity),
		encoding.EncodeVector(clientIdentity),
	)
}

// Store returns the client's Envelope, the masking key for the registration, and the additional export key.
func Store(
	conf *internal.Configuration,
	randomizedPwd []byte, serverPublicKey *group.Element,
	creds *Credentials,
) (env *Envelope, pku *group.Element, export []byte) {
	// testing: integrated to support testing with set nonce
	nonce := creds.EnvelopeNonce
	if nonce == nil {
		nonce = internal.RandomBytes(conf.NonceLen)
	}

	pku = getPubkey(conf, randomizedPwd, nonce)
	ctc := cleartextCredentials(
		pku.Encode(),
		serverPublicKey.Encode(),
		creds.ClientIdentity,
		creds.ServerIdentity,
	)
	auth := authTag(conf, randomizedPwd, nonce, ctc)
	export = exportKey(conf, randomizedPwd, nonce)

	env = &Envelope{
		Nonce:   nonce,
		AuthTag: auth,
	}

	return env, pku, export
}

// Recover returns the client's private and public key, as well as the secret export key.
func Recover(
	conf *internal.Configuration,
	randomizedPwd, serverPublicKey, clientIdentity, serverIdentity []byte,
	envelope *Envelope,
) (clientSecretKey *group.Scalar, clientPublicKey *group.Element, export []byte, err error) {
	clientSecretKey, clientPublicKey = recoverKeys(conf, randomizedPwd, envelope.Nonce)
	ctc := cleartextCredentials(
		clientPublicKey.Encode(),
		serverPublicKey,
		clientIdentity,
		serverIdentity,
	)

	expectedTag := authTag(conf, randomizedPwd, envelope.Nonce, ctc)
	if !conf.MAC.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, errEnvelopeInvalidMac
	}

	export = exportKey(conf, randomizedPwd, envelope.Nonce)

	return clientSecretKey, clientPublicKey, export, nil
}
