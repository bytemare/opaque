// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package masking provides the credential masking mechanism.
package masking

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/tag"
)

// errInvalidPKS happens when the server sends an invalid public key.
var errInvalidPKS = errors.New("invalid server public key")

// Keys contains all the output keys from the masking mechanism.
type Keys struct {
	ClientSecretKey                  *group.Scalar
	ClientPublicKey, ServerPublicKey *group.Point
	ExportKey, ServerPublicKeyBytes  []byte
}

// Mask encrypts the serverPublicKey and the envelope under nonceIn and the maskingKey.
func Mask(p *internal.Parameters, nonceIn, maskingKey, serverPublicKey, envelope []byte) (nonce, maskedResponse []byte) {
	// testing: integrated to support testing, to force values.
	nonce = nonceIn
	if len(nonce) == 0 {
		nonce = internal.RandomBytes(p.NonceLen)
	}

	clear := encoding.Concat(serverPublicKey, envelope)
	maskedResponse = p.XorResponse(maskingKey, nonce, clear)

	return nonce, maskedResponse
}

// Unmask decrypts the maskedResponse and returns the server's public key and the client key on success.
// This function assumes that maskedResponse has been checked to be of length pointLength + envelope size.
func Unmask(p *internal.Parameters, randomizedPwd, nonce, maskedResponse []byte) (serverPublicKey *group.Point,
	serverPublicKeyBytes []byte, envelope *keyrecovery.Envelope, err error) {
	maskingKey := p.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), p.Hash.Size())
	clear := p.XorResponse(maskingKey, nonce, maskedResponse)
	serverPublicKeyBytes = clear[:encoding.PointLength[p.Group]]
	env := clear[encoding.PointLength[p.Group]:]
	envelope = &keyrecovery.Envelope{
		Nonce:   env[:p.NonceLen],
		AuthTag: env[p.NonceLen:],
	}

	serverPublicKey, err = p.Group.NewElement().Decode(serverPublicKeyBytes)
	if err != nil {
		return nil, nil, nil, errInvalidPKS
	}

	return serverPublicKey, serverPublicKeyBytes, envelope, nil
}
