// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package envelope provides utility functions and structures allowing credential management.
package envelope

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var (
	errEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")
	errBuildInvalidSK     = errors.New("can't build envelope: invalid secret key encoding")
	errRecoverInvalidSK   = errors.New("can't recover envelope: invalid secret key encoding")
)

// Credentials is currently used for testing purposes.
type Credentials struct {
	Idc, Ids                    []byte
	EnvelopeNonce, MaskingNonce []byte // testing: integrated to support testing
}

// Mode determines the envelope mode to operate in.
type Mode byte

// Internal and External define the Envelope modes.
const (
	Internal Mode = iota + 1
	External
)

var modes = map[Mode]innerEnvelope{
	Internal: &internalMode{},
	External: &externalMode{},
}

// IsValidMode returns whether m is a valid envelope mode.
func IsValidMode(m Mode) bool {
	_, ok := modes[m]
	return ok
}

// Envelope represents the OPAQUE envelope.
type Envelope struct {
	Nonce         []byte
	InnerEnvelope []byte
	AuthTag       []byte
}

// Serialize returns the byte serialization of the envelope.
func (e *Envelope) Serialize() []byte {
	return encoding.Concat3(e.Nonce, e.InnerEnvelope, e.AuthTag)
}

type innerEnvelope interface {
	buildInnerEnvelope(m *sheath, randomizedPwd, nonce, clientSecretKey []byte) (innerEnvelope, pk []byte, err error)
	recoverKeys(m *sheath, randomizedPwd, nonce, innerEnvelope []byte) (clientSecretKey *group.Scalar, clientPublicKey *group.Point, err error)
}

// BuildPRK derives the randomized password from the OPRF output.
func BuildPRK(p *internal.Parameters, unblinded []byte) []byte {
	hardened := p.MHF.Harden(unblinded, nil, p.OPRFPointLength)
	return p.KDF.Extract(nil, hardened)
}

// sheath is a utility structure to manage envelope creation and recovery.
type sheath struct {
	*internal.Parameters
}

func (m *sheath) exportKey(randomizedPwd, nonce []byte) []byte {
	return m.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExportKey), m.KDF.Size())
}

func (m *sheath) authTag(randomizedPwd, nonce, inner, ctc []byte) []byte {
	authKey := m.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.AuthKey), m.KDF.Size())
	return m.MAC.MAC(authKey, encoding.Concat3(nonce, inner, ctc))
}

func (m *sheath) createEnvelope(mode Mode, randomizedPwd, serverPublicKey, clientSecretKey []byte,
	creds *Credentials) (envelope *Envelope, publicKey, exportKey []byte, err error) {
	// testing: integrated to support testing with set nonce
	nonce := creds.EnvelopeNonce
	if nonce == nil {
		nonce = internal.RandomBytes(m.NonceLen)
	}

	inner, clientPublicKey, err := modes[mode].buildInnerEnvelope(m, randomizedPwd, nonce, clientSecretKey)
	if err != nil {
		return nil, nil, nil, err
	}

	ctc := cleartextCredentials(clientPublicKey, serverPublicKey, creds.Idc, creds.Ids)
	authTag := m.authTag(randomizedPwd, nonce, inner, ctc)

	envelope = &Envelope{
		Nonce:         nonce,
		InnerEnvelope: inner,
		AuthTag:       authTag,
	}

	exportKey = m.exportKey(randomizedPwd, nonce)

	return envelope, clientPublicKey, exportKey, nil
}

// RecoverEnvelope assumes that the envelope's inner envelope has been previously checked to be of correct size.
func RecoverEnvelope(p *internal.Parameters, mode Mode, randomizedPwd, serverPublicKey, idc, ids []byte,
	envelope *Envelope) (clientSecretKey *group.Scalar, clientPublicKey *group.Point, exportKey []byte, err error) {
	m := &sheath{p}

	clientSecretKey, clientPublicKey, err = modes[mode].recoverKeys(m, randomizedPwd, envelope.Nonce, envelope.InnerEnvelope)
	if err != nil {
		return nil, nil, nil, err
	}

	ctc := cleartextCredentials(clientPublicKey.Bytes(), serverPublicKey, idc, ids)

	expectedTag := m.authTag(randomizedPwd, envelope.Nonce, envelope.InnerEnvelope, ctc)
	if !m.MAC.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, errEnvelopeInvalidTag
	}

	exportKey = m.exportKey(randomizedPwd, envelope.Nonce)

	return clientSecretKey, clientPublicKey, exportKey, nil
}
