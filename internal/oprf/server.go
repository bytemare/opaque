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
	"fmt"

	"github.com/bytemare/cryptotools/group"
)

type Server struct {
	*oprf
	privateKey group.Scalar
}

func (s *Server) Evaluate(blindedElement []byte) ([]byte, error) {
	b, err := s.group.NewElement().Decode(blindedElement)
	if err != nil {
		return nil, fmt.Errorf("can't evaluate input : %w", err)
	}

	return b.Mult(s.privateKey).Bytes(), nil
}
