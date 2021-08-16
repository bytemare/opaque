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
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

type externalMode struct{}

func (e *externalMode) recoverPublicKey(m *mailer, privateKey *group.Scalar) *group.Point {
	return m.Group.Base().Mult(privateKey)
}

func (e *externalMode) crypt(m *mailer, randomizedPwd, nonce, input []byte) []byte {
	pad := m.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.EncryptionPad), encoding.ScalarLength[m.Group])
	return internal.Xor(input, pad)
}

func (e *externalMode) buildInnerEnvelope(m *mailer,
	randomizedPwd, nonce, clientSecretKey []byte) (innerEnvelope, pk []byte, err error) {
	scalar, err := m.Group.NewScalar().Decode(clientSecretKey)
	if err != nil {
		return nil, nil, errBuildInvalidSK
	}

	clientPublicKey := e.recoverPublicKey(m, scalar)

	return e.crypt(m, randomizedPwd, nonce, clientSecretKey), encoding.SerializePoint(clientPublicKey, m.Group), nil
}

func (e *externalMode) recoverKeys(m *mailer,
	randomizedPwd, nonce, innerEnvelope []byte) (sk *group.Scalar, clientPublicKey *group.Point, err error) {
	clientSecretKey := e.crypt(m, randomizedPwd, nonce, innerEnvelope)

	sk, err = m.Group.NewScalar().Decode(clientSecretKey)
	if err != nil {
		return nil, nil, errRecoverInvalidSK
	}

	return sk, e.recoverPublicKey(m, sk), nil
}
