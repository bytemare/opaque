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
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

type externalMode struct {
	ciphersuite.Identifier
	*internal.KDF
}

func (e *externalMode) recoverPublicKey(privateKey group.Scalar) group.Element {
	return e.Base().Mult(privateKey)
}

func (e *externalMode) crypt(randomizedPwd, nonce, input []byte) []byte {
	pad := e.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.EncryptionPad), len(input))
	return internal.Xor(input, pad)
}

func (e *externalMode) buildInnerEnvelope(randomizedPwd, nonce, clientSecretKey []byte) (innerEnvelope, pk []byte, err error) {
	scalar, err := e.NewScalar().Decode(clientSecretKey)
	if err != nil {
		return nil, nil, errBuildInvalidSK
	}

	clientPublicKey := e.recoverPublicKey(scalar)

	return e.crypt(randomizedPwd, nonce, clientSecretKey), encoding.SerializePoint(clientPublicKey, e.Identifier), nil
}

func (e *externalMode) recoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (sk group.Scalar, clientPublicKey group.Element, err error) {
	clientSecretKey := e.crypt(randomizedPwd, nonce, innerEnvelope)

	sk, err = e.NewScalar().Decode(clientSecretKey)
	if err != nil {
		return nil, nil, errRecoverInvalidSK
	}

	return sk, e.recoverPublicKey(sk), nil
}
