// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package oprf implements the Elliptic Curve Oblivious Pseudorandom Function (EC-OPRF) from https://tools.ietf.org/html/draft-irtf-cfrg-voprf.
package oprf

import (
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

func (c Ciphersuite) pTag(info []byte) *group.Scalar {
	o := c.oprf()
	context := encoding.Concat3([]byte(tag.OPRFContextPrefix), o.contextString, encoding.EncodeVector(info))

	return c.Group().HashToScalar(context, o.dst(tag.OPRFScalarPrefix))
}

// Evaluate evaluates the blinded input with the given key.
func (c Ciphersuite) Evaluate(privateKey *group.Scalar, blindedElement *group.Point, info []byte) *group.Point {
	context := c.pTag(info)
	inv := privateKey.Add(context).Invert()

	return blindedElement.Mult(inv)
}
