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

	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

var (
	errEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")
	errBuildInvalidSK     = errors.New("can't build envelope: invalid secret key encoding")
	errRecoverInvalidSK   = errors.New("can't recover envelope: invalid secret key encoding")
)

type Credentials struct {
	Idc, Ids                    []byte
	EnvelopeNonce, MaskingNonce []byte // testing: integrated to support testing
}

type Mode byte

// Internal and External define the Envelope modes.
const (
	Internal Mode = iota + 1
	External
)

type Envelope struct {
	Nonce         []byte
	InnerEnvelope []byte
	AuthTag       []byte
}

func (e *Envelope) Serialize() []byte {
	return encoding.Concat3(e.Nonce, e.InnerEnvelope, e.AuthTag)
}

type innerEnvelope interface {
	buildInnerEnvelope(randomizedPwd, nonce, clientSecretKey []byte) (innerEnvelope, pk []byte, err error)
	recoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (clientSecretKey group.Scalar, clientPublicKey group.Element, err error)
}

func BuildPRK(p *internal.Parameters, unblinded []byte) []byte {
	// testing: commented out to support testing. hardened := p.Harden(unblinded, nil)
	hardened := unblinded
	return p.KDF.Extract(nil, hardened)
}

type Mailer struct {
	*internal.Parameters
}

func (m *Mailer) inner(mode Mode) innerEnvelope {
	var inner innerEnvelope

	switch mode {
	case Internal:
		inner = &internalMode{m.AKEGroup, m.KDF}
	case External:
		inner = &externalMode{m.AKEGroup, m.AKEGroup.Get(), m.KDF}
	default:
		panic("invalid mode")
	}

	return inner
}

func (m *Mailer) buildKeys(randomizedPwd, nonce []byte) (authKey, exportKey []byte) {
	authKey = m.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.AuthKey), m.KDF.Size())
	exportKey = m.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExportKey), m.KDF.Size())

	return
}

func (m *Mailer) authTag(authKey, nonce, inner, ctc []byte) []byte {
	return m.MAC.MAC(authKey, encoding.Concat3(nonce, inner, ctc))
}

func (m *Mailer) CreateEnvelope(mode Mode, randomizedPwd, serverPublicKey, clientSecretKey []byte,
	creds *Credentials) (envelope *Envelope, publicKey, exportKey []byte, err error) {
	// testing: integrated to support testing with set nonce
	nonce := creds.EnvelopeNonce
	if nonce == nil {
		nonce = internal.RandomBytes(m.NonceLen)
	}

	authKey, exportKey := m.buildKeys(randomizedPwd, nonce)

	inner, clientPublicKey, err := m.inner(mode).buildInnerEnvelope(randomizedPwd, nonce, clientSecretKey)
	if err != nil {
		return nil, nil, nil, err
	}

	ctc := CreateCleartextCredentials(clientPublicKey, serverPublicKey, creds.Idc, creds.Ids)
	authTag := m.authTag(authKey, nonce, inner, ctc.Serialize())

	envelope = &Envelope{
		Nonce:         nonce,
		InnerEnvelope: inner,
		AuthTag:       authTag,
	}

	return envelope, clientPublicKey, exportKey, nil
}

// RecoverEnvelope assumes that the envelope's inner envelope has been previously checked to be of correct size.
func (m *Mailer) RecoverEnvelope(mode Mode, randomizedPwd, serverPublicKey, idc, ids []byte,
	envelope *Envelope) (clientSecretKey group.Scalar, clientPublicKey group.Element, exportKey []byte, err error) {
	authKey, exportKey := m.buildKeys(randomizedPwd, envelope.Nonce)

	clientSecretKey, clientPublicKey, err = m.inner(mode).recoverKeys(randomizedPwd, envelope.Nonce, envelope.InnerEnvelope)
	if err != nil {
		return nil, nil, nil, err
	}

	ctc := CreateCleartextCredentials(clientPublicKey.Bytes(), serverPublicKey, idc, ids)

	expectedTag := m.authTag(authKey, envelope.Nonce, envelope.InnerEnvelope, ctc.Serialize())
	if !m.MAC.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, errEnvelopeInvalidTag
	}

	return clientSecretKey, clientPublicKey, exportKey, nil
}
