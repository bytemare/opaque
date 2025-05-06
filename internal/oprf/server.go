// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package oprf

import (
	"github.com/bytemare/ecc"
)

// Evaluate evaluates the blinded input with the given key.
func (i Identifier) Evaluate(privateKey *ecc.Scalar, blindedElement *ecc.Element) *ecc.Element {
	return blindedElement.Copy().Multiply(privateKey)
}
