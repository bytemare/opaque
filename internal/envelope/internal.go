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

type internalMode struct {
	group.Group
	*internal.KDF
}

func (i *internalMode) deriveAkeKeyPair(randomizedPwd, nonce []byte) (*group.Scalar, *group.Point) {
	seed := i.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), encoding.ScalarLength[i.Group])
	sk := i.HashToScalar(seed, []byte(tag.DerivePrivateKey))

	return sk, i.Base().Mult(sk)
}

func (i *internalMode) buildInnerEnvelope(randomizedPwd, nonce, _ []byte) (inner, clientPublicKey []byte, err error) {
	_, pk := i.deriveAkeKeyPair(randomizedPwd, nonce)
	return nil, encoding.SerializePoint(pk, i.Group), nil
}

func (i *internalMode) recoverKeys(randomizedPwd, nonce, _ []byte) (clientSecretKey *group.Scalar, clientPublicKey *group.Point, err error) {
	sk, pk := i.deriveAkeKeyPair(randomizedPwd, nonce)
	return sk, pk, nil
}
