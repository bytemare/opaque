// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keyrecovery

import (
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
)

func deriveAuthKeyPair(conf *internal.Configuration, randomizedPwd, nonce []byte) (*group.Scalar, *group.Point) {
	seed := conf.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), internal.SeedLength)
	sk := oprf.Ciphersuite(conf.Group).DeriveKey(seed, []byte(tag.DerivePrivateKey))

	return sk, conf.Group.Base().Mult(sk)
}

func getPubkey(conf *internal.Configuration, randomizedPwd, nonce []byte) *group.Point {
	_, pk := deriveAuthKeyPair(conf, randomizedPwd, nonce)
	return pk
}

func recoverKeys(
	conf *internal.Configuration,
	randomizedPwd, nonce []byte,
) (clientSecretKey *group.Scalar, clientPublicKey *group.Point) {
	return deriveAuthKeyPair(conf, randomizedPwd, nonce)
}
