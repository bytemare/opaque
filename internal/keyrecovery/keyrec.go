// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package keyrecovery

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
)

func deriveAuthKeyPair(conf *internal.Configuration, randomizedPwd, nonce []byte) (*group.Scalar, *group.Element) {
	seed := conf.KDF.Expand(randomizedPwd, encoding.SuffixString(nonce, tag.ExpandPrivateKey), internal.SeedLength)
	sk := oprf.IDFromGroup(conf.Group).DeriveKey(seed, []byte(tag.DerivePrivateKey))

	return sk, conf.Group.Base().Multiply(sk)
}

func getPubkey(conf *internal.Configuration, randomizedPwd, nonce []byte) *group.Element {
	_, pk := deriveAuthKeyPair(conf, randomizedPwd, nonce)
	return pk
}

func recoverKeys(
	conf *internal.Configuration,
	randomizedPwd, nonce []byte,
) (clientSecretKey *group.Scalar, clientPublicKey *group.Element) {
	return deriveAuthKeyPair(conf, randomizedPwd, nonce)
}
