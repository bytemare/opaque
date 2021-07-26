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

type internalMode struct {
	ciphersuite.Identifier
	*internal.KDF
}

func (i *internalMode) deriveSecretKey(seed []byte) group.Scalar {
	return i.HashToScalar(seed, []byte(tag.DerivePrivateKey))
}

func (i *internalMode) deriveAkeKeyPair(seed []byte) (group.Scalar, group.Element) {
	sk := i.deriveSecretKey(seed)
	return sk, i.Base().Mult(sk)
}

func (i *internalMode) buildInnerEnvelope(randomizedPwd, nonce, _ []byte) (inner, clientPublicKey []byte, err error) {
	seed := i.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), encoding.ScalarLength[i.Identifier])
	_, pk := i.deriveAkeKeyPair(seed)

	return nil, encoding.SerializePoint(pk, i.Identifier), nil
}

func (i *internalMode) recoverKeys(randomizedPwd, nonce, _ []byte) (clientSecretKey group.Scalar, clientPublicKey group.Element, err error) {
	seed := i.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), encoding.ScalarLength[i.Identifier])
	sk, pk := i.deriveAkeKeyPair(seed)

	return sk, pk, nil
}
