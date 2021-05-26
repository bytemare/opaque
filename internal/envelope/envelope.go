// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package envelope provides utility functions and structures allowing credential management.
package envelope

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/opaque/internal/encoding"

	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
)

var (
	errEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")
	errCorruptEnvelope    = errors.New("envelope corrupted")
	errInvalidEnvLength   = errors.New("envelope of invalid length")
	errInvalidSK          = errors.New("invalid private key")
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

func (e *Envelope) String() string {
	return fmt.Sprintf("Nonce: %v\nAuthTag: %v\nInnerEnvelope: %v\n", e.Nonce, e.AuthTag, e.InnerEnvelope)
}

func (e *Envelope) Serialize() []byte {
	return utils.Concatenate(0, e.Nonce, e.InnerEnvelope, e.AuthTag)
}

func Size(mode Mode, p *internal.Parameters) int {
	var innerSize int

	switch mode {
	case Internal:
		innerSize = 0
	case External:
		innerSize = encoding.ScalarLength[p.AKEGroup]
	default:
		panic("invalid envelope mode")
	}

	return p.NonceLen + p.MAC.Size() + innerSize
}

func DeserializeEnvelope(data []byte, mode Mode, nn, nm, nsk int) (*Envelope, int, error) {
	baseLen := nn + nm

	if len(data) < baseLen {
		return nil, 0, errCorruptEnvelope
	}

	if mode == External && len(data) != baseLen+nsk {
		return nil, 0, errInvalidEnvLength
	}

	nonce := data[:nn]
	innerLen := 0

	if mode == External {
		innerLen = nsk
	}

	inner := data[nn : nn+innerLen]
	tag := data[nn+innerLen:]

	return &Envelope{
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}, baseLen + len(inner), nil
}

type innerEnvelope interface {
	buildInnerEnvelope(randomizedPwd, nonce, clientSecretKey []byte) (innerEnvelope, pk []byte)
	recoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (clientSecretKey []byte, clientPublicKey group.Element)
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
		inner = &externalMode{encoding.ScalarLength[m.AKEGroup], m.AKEGroup.Get(nil), m.KDF}
	default:
		panic("invalid mode")
	}

	return inner
}

func (m *Mailer) buildKeys(randomizedPwd, nonce []byte) (authKey, exportKey []byte) {
	authKey = m.KDF.Expand(randomizedPwd, encoding.Concat(nonce, internal.TagAuthKey), m.KDF.Size())
	exportKey = m.KDF.Expand(randomizedPwd, encoding.Concat(nonce, internal.TagExportKey), m.KDF.Size())

	return
}

func (m *Mailer) authTag(authKey, nonce, inner, ctc []byte) []byte {
	return m.MAC.MAC(authKey, utils.Concatenate(0, nonce, inner, ctc))
}

func (m *Mailer) CreateEnvelope(mode Mode, randomizedPwd, serverPublicKey, clientSecretKey []byte,
	creds *Credentials) (envelope *Envelope, publicKey, exportKey []byte) {
	// testing: integrated to support testing
	nonce := creds.EnvelopeNonce
	if nonce == nil {
		nonce = utils.RandomBytes(m.NonceLen)
	}

	authKey, exportKey := m.buildKeys(randomizedPwd, nonce)
	inner, clientPublicKey := m.inner(mode).buildInnerEnvelope(randomizedPwd, nonce, clientSecretKey)
	ctc := CreateCleartextCredentials(clientPublicKey, serverPublicKey, creds.Idc, creds.Ids)
	tag := m.authTag(authKey, nonce, inner, ctc.Serialize())

	envelope = &Envelope{
		Nonce:         nonce,
		InnerEnvelope: inner,
		AuthTag:       tag,
	}

	return envelope, clientPublicKey, exportKey
}

func (m *Mailer) RecoverEnvelope(mode Mode, randomizedPwd, serverPublicKey, idc, ids []byte,
	envelope *Envelope) (clientSecretKey []byte, clientPublicKey group.Element, exportKey []byte, err error) {
	authKey, exportKey := m.buildKeys(randomizedPwd, envelope.Nonce)
	clientSecretKey, clientPublicKey = m.inner(mode).recoverKeys(randomizedPwd, envelope.Nonce, envelope.InnerEnvelope)
	ctc := CreateCleartextCredentials(clientPublicKey.Bytes(), serverPublicKey, idc, ids)

	expectedTag := m.authTag(authKey, envelope.Nonce, envelope.InnerEnvelope, ctc.Serialize())
	if !hmac.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, errEnvelopeInvalidTag
	}

	return clientSecretKey, clientPublicKey, exportKey, nil
}
