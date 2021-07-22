// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package envelope provides utility functions and structures allowing credential management.
package envelope

import "github.com/bytemare/opaque/internal/encoding"

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

	return encoding.Concat3(c.Pks, s, u)
}

// CreateCleartextCredentials assumes that clientPublicKey, serverPublicKey are non-nil valid group elements.
func CreateCleartextCredentials(clientPublicKey, serverPublicKey, idc, ids []byte) *CleartextCredentials {
	if idc == nil {
		idc = clientPublicKey
	}

	if ids == nil {
		ids = serverPublicKey
	}

	return &CleartextCredentials{
		Pks: serverPublicKey,
		Idc: idc,
		Ids: ids,
	}
}
