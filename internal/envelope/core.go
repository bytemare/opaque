// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package envelope

import (
	"fmt"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
)

// Core holds the Client state between the key derivation steps,
// and exposes envelope creation and key recovery functions.
type Core struct {
	Oprf *oprf.Client
}

// New returns a pointer to an instantiated Core structure.
func New(id oprf.Ciphersuite) *Core {
	return &Core{
		Oprf: id.Client(),
	}
}

// OprfStart initiates the OPRF by blinding the password.
func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

// OprfFinalize terminates the OPRF by unblinding the evaluated data.
func (c *Core) OprfFinalize(data []byte) ([]byte, error) {
	return c.Oprf.Finalize(data)
}

// BuildEnvelope returns the client's Envelope, the masking key for the registration, and the additional export key.
func (c *Core) BuildEnvelope(p *internal.Parameters, mode Mode, evaluation, serverPublicKey, clientSecretKey []byte,
	creds *Credentials) (env *Envelope, clientPublicKey, maskingKey, exportKey []byte, err error) {
	unblinded, err := c.OprfFinalize(evaluation)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := BuildPRK(p, unblinded)
	m := &sheath{Parameters: p}

	env, clientPublicKey, exportKey, err = m.createEnvelope(mode, randomizedPwd, serverPublicKey, clientSecretKey, creds)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	maskingKey = m.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), m.KDF.Size())

	return env, clientPublicKey, maskingKey, exportKey, nil
}
