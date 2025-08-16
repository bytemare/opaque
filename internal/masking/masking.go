// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package masking provides the credential masking mechanism.
package masking

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/tag"
)

// ErrPublicKeyIdentity happens when the public key is the identity element (point at infinity).
var ErrPublicKeyIdentity = errors.New("public key is identity element")

// Keys contains all the output keys from the masking mechanism.
type Keys struct {
	ClientSecretKey                  *ecc.Scalar
	ClientPublicKey, ServerPublicKey *ecc.Element
	ExportKey, ServerPublicKeyBytes  []byte
}

// Mask encrypts the serverPublicKey and the envelope under nonceIn and the maskingKey.
func Mask(
	conf *internal.Configuration,
	nonceIn, maskingKey, serverPublicKey, envelope []byte,
) (nonce, maskedResponse []byte) {
	nonce = nonceIn
	if len(nonce) == 0 {
		nonce = internal.RandomBytes(conf.NonceLen)
	}

	clearText := encoding.Concat(serverPublicKey, envelope)
	maskedResponse = xorResponse(conf, maskingKey, nonce, clearText)

	return nonce, maskedResponse
}

// Unmask decrypts the maskedResponse and returns the server's public key and the client key on success.
// This function assumes that maskedResponse has been checked to be of length pointLength + envelope size.
func Unmask(
	conf *internal.Configuration,
	randomizedPassword, nonce, maskedResponse []byte,
) (serverPublicKey *ecc.Element, serverPublicKeyBytes []byte, envelope *keyrecovery.Envelope, err error) {
	maskingKey := conf.KDF.Expand(randomizedPassword, []byte(tag.MaskingKey), conf.Hash.Size())
	clearText := xorResponse(conf, maskingKey, nonce, maskedResponse)
	serverPublicKeyBytes = clearText[:conf.Group.ElementLength()]
	env := clearText[conf.Group.ElementLength():]
	envelope = &keyrecovery.Envelope{
		Nonce:   env[:conf.NonceLen],
		AuthTag: env[conf.NonceLen:],
	}

	serverPublicKey = conf.Group.NewElement()
	if err = serverPublicKey.Decode(serverPublicKeyBytes); err != nil {
		return nil, nil, nil, err
	}

	return serverPublicKey, serverPublicKeyBytes, envelope, nil
}

// xorResponse is used to encrypt and decrypt the response in KE2.
// It returns a new byte slice containing the byte-by-byte xor-ing of the in argument and a constructed pad,
// which must be of the same length.
func xorResponse(c *internal.Configuration, key, nonce, in []byte) []byte {
	pad := c.KDF.Expand(
		key,
		encoding.SuffixString(nonce, tag.CredentialResponsePad),
		c.Group.ElementLength()+c.EnvelopeSize,
	)

	dst := make([]byte, len(pad))

	// if the size is fixed, we could unroll the loop
	for i, r := range pad {
		dst[i] = r ^ in[i]
	}

	return dst
}
