// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package envelope provides utility functions and structures allowing credential management.
package envelope

import "github.com/bytemare/opaque/internal/encoding"

// cleartextCredentials assumes that clientPublicKey, serverPublicKey are non-nil valid group elements.
func cleartextCredentials(clientPublicKey, serverPublicKey, idc, ids []byte) []byte {
	if ids == nil {
		ids = serverPublicKey
	}

	if idc == nil {
		idc = clientPublicKey
	}

	return encoding.Concat3(serverPublicKey, encoding.EncodeVector(ids), encoding.EncodeVector(idc))
}
