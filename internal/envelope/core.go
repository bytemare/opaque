// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package envelope

import (
	"fmt"

	"github.com/bytemare/voprf"

	"github.com/bytemare/opaque/internal"
)

// Core holds the Client state between the key derivation steps,
// and exposes envelope creation and key recovery functions.
type Core struct {
	Oprf *voprf.Client
	*internal.Parameters
}

// New returns a pointer to an instantiated Core structure.
func New(parameters *internal.Parameters) *Core {
	oprf, err := parameters.OprfCiphersuite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Oprf:       oprf,
		Parameters: parameters,
	}
}

// OprfStart initiates the OPRF by blinding the password.
func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

// OprfFinalize terminates the OPRF by unblinding the evaluated data.
func (c *Core) OprfFinalize(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}

	u, err := c.Oprf.Finalize(ev)
	if err != nil {
		err = fmt.Errorf("oprf finalization: %w", err)
	}

	return u, err
}

// BuildEnvelope returns the client's Envelope, the masking key for the registration, and the additional export key.
func (c *Core) BuildEnvelope(mode Mode, evaluation, serverPublicKey, clientSecretKey []byte,
	creds *Credentials) (env *Envelope, clientPublicKey, maskingKey, exportKey []byte, err error) {
	unblinded, err := c.OprfFinalize(evaluation)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := BuildPRK(c.Parameters, unblinded)
	m := &Mailer{Parameters: c.Parameters}
	env, clientPublicKey, exportKey = m.CreateEnvelope(mode, randomizedPwd, serverPublicKey, clientSecretKey, creds)
	maskingKey = m.KDF.Expand(randomizedPwd, []byte(internal.TagMaskingKey), m.KDF.Size())

	return env, clientPublicKey, maskingKey, exportKey, nil
}
