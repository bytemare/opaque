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
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal/encoding"
)

type CleartextCredentials struct {
	Pks []byte
	Idc []byte
	Ids []byte
}

func (c *CleartextCredentials) Serialize() []byte {
	var u, s []byte
	if c.Idc != nil {
		u = encoding.EncodeVector(c.Idc)
	}

	if c.Ids != nil {
		s = encoding.EncodeVector(c.Ids)
	}

	return utils.Concatenate(0, c.Pks, s, u)
}

func CreateCleartextCredentials(clientPublicKey, pks, idc, ids []byte) *CleartextCredentials {
	if pks == nil {
		panic("nil pks")
	}

	if clientPublicKey == nil {
		panic("nil clientPublicKey")
	}

	if idc == nil {
		idc = clientPublicKey
	}

	if ids == nil {
		ids = pks
	}

	return &CleartextCredentials{
		Pks: pks,
		Idc: idc,
		Ids: ids,
	}
}
