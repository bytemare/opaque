// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

import (
	group "github.com/bytemare/crypto"
)

const (
	ristrettoPointLength = 32
	p256PointLength      = 33
	p384PointLength      = 49
	p521PointLength      = 67
)

// PointLength indexes the length of elements.
var PointLength = map[group.Group]int{
	group.Ristretto255Sha512: ristrettoPointLength,
	// group.Decaf448Shake256: 56,
	group.P256Sha256: p256PointLength,
	group.P384Sha384: p384PointLength,
	group.P521Sha512: p521PointLength,
}
