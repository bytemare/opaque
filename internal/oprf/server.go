// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package oprf

import (
	group "github.com/bytemare/crypto"
)

// Evaluate evaluates the blinded input with the given key.
func (c Ciphersuite) Evaluate(privateKey *group.Scalar, blindedElement *group.Element) *group.Element {
	return blindedElement.Copy().Multiply(privateKey)
}
