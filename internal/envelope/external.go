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
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/opaque/internal/encoding"

	"github.com/bytemare/opaque/internal"
)

type externalInnerEnvelope struct {
	encrypted []byte
}

func (e externalInnerEnvelope) serialize() []byte {
	return e.encrypted
}

func deserializeExternalInnerEnvelope(inner []byte, nsk int) *externalInnerEnvelope {
	if len(inner) != nsk {
		panic("invalid inner envelope")
	}

	return &externalInnerEnvelope{inner}
}

type externalMode struct {
	Nsk int
	group.Group
	*internal.KDF
}

func (e *externalMode) recoverPublicKey(privateKey group.Scalar) group.Element {
	return e.Base().Mult(privateKey)
}

func (e *externalMode) buildInnerEnvelope(randomizedPwd, nonce, clientSecretKey []byte) (innerEnvelope, pk []byte) {
	scalar, err := e.NewScalar().Decode(clientSecretKey)
	if err != nil {
		panic(errInvalidSK)
	}

	clientPublicKey := e.Base().Mult(scalar)
	pad := e.Expand(randomizedPwd, encoding.Concat(nonce, internal.TagPad), len(clientSecretKey))

	return externalInnerEnvelope{internal.Xor(clientSecretKey, pad)}.serialize(), clientPublicKey.Bytes()
}

func (e *externalMode) recoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (clientSecretKey []byte, clientPublicKey group.Element) {
	inner := deserializeExternalInnerEnvelope(innerEnvelope, e.Nsk)
	pad := e.Expand(randomizedPwd, encoding.Concat(nonce, internal.TagPad), len(inner.encrypted))
	clientSecretKey = internal.Xor(inner.encrypted, pad)

	sk, err := e.NewScalar().Decode(clientSecretKey)
	if err != nil {
		panic(errInvalidSK)
	}

	return clientSecretKey, e.recoverPublicKey(sk)
}
