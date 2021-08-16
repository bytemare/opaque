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

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

type internalMode struct{}

func (i *internalMode) deriveAkeKeyPair(m *mailer, randomizedPwd, nonce []byte) (*group.Scalar, *group.Point) {
	seed := m.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), encoding.ScalarLength[m.Group])
	sk := m.Group.HashToScalar(seed, []byte(tag.DerivePrivateKey))

	return sk, m.Group.Base().Mult(sk)
}

func (i *internalMode) buildInnerEnvelope(m *mailer,
	randomizedPwd, nonce, _ []byte) (inner, clientPublicKey []byte, err error) {
	_, pk := i.deriveAkeKeyPair(m, randomizedPwd, nonce)
	return nil, encoding.SerializePoint(pk, m.Group), nil
}

func (i *internalMode) recoverKeys(m *mailer,
	randomizedPwd, nonce, _ []byte) (clientSecretKey *group.Scalar, clientPublicKey *group.Point, err error) {
	sk, pk := i.deriveAkeKeyPair(m, randomizedPwd, nonce)
	return sk, pk, nil
}
