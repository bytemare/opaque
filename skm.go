// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"encoding/hex"
	"errors"
	"slices"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
)

// ServerKeyMaterial holds the server's long-term identity and key material for OPAQUE registration and authentication
// sessions. Note that, depending on the setup, these values are not client specific and can be reused across clients.
type ServerKeyMaterial struct {
	// The server's long-term secret key. Required only for Login, and not used in Registration.
	PrivateKey *ecc.Scalar

	// The server's public key in bytes. Must be provided during registration and login.
	PublicKeyBytes []byte

	// The seed to derive the OPRF key for the clients with. Required if client OPRF keys won't be provided directly.
	OPRFGlobalSeed []byte

	// The server's identity. If empty, the server's public key will be used as the identity.
	Identity []byte
}

// Flush does a best-effort attempt to clear the server key material from memory. It is not guaranteed that the contents
// are correctly wiped from memory.
func (s *ServerKeyMaterial) Flush() {
	internal.ClearScalar(&s.PrivateKey)
	internal.ClearSlice(&s.PublicKeyBytes)
	internal.ClearSlice(&s.OPRFGlobalSeed)
	internal.ClearSlice(&s.Identity)
}

// Encode encodes the server key material into a byte slice.
func (s *ServerKeyMaterial) Encode() []byte {
	return encoding.Concatenate(
		[]byte{byte(s.PrivateKey.Group())},
		encoding.EncodeVector(s.PrivateKey.Encode()),
		encoding.EncodeVector(s.PublicKeyBytes),
		encoding.EncodeVector(s.OPRFGlobalSeed),
		encoding.EncodeVector(s.Identity),
	)
}

// Hex encodes the server key material into a hex string.
func (s *ServerKeyMaterial) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// DecodeServerKeyMaterial decodes the server key material from a byte slice.
func (c *Configuration) DecodeServerKeyMaterial(data []byte) (*ServerKeyMaterial, error) {
	if err := c.skmStructureCheck(data); err != nil {
		return nil, ErrServerKeyMaterial.Join(err)
	}

	var skBytes, pkBytes, seed, id []byte
	if err := encoding.DecodeLongVector(data[1:], &skBytes, &pkBytes, &seed, &id); err != nil {
		return nil, ErrServerKeyMaterial.Join(err)
	}

	g := c.AKE.Group()

	sk, err := DeserializeScalar(g, skBytes)
	if err != nil {
		return nil, ErrServerKeyMaterial.Join(internal.ErrInvalidPrivateKey, err)
	}

	pk, err := DeserializeElement(g, pkBytes)
	if err != nil {
		return nil, ErrServerKeyMaterial.Join(
			internal.ErrInvalidServerPublicKey,
			internal.ErrInvalidPublicKeyBytes,
			err,
		)
	}

	if c.AKE.Group().Base().Equal(pk) {
		return nil, ErrServerKeyMaterial.Join(internal.ErrInvalidServerPublicKey, internal.ErrElementIsBase)
	}

	if !pk.Equal(g.Base().Multiply(sk)) {
		return nil, ErrServerKeyMaterial.Join(internal.ErrInvalidServerPublicKey)
	}

	// The following is never triggered due to the structure check and failsafe above, but is kept for safety.
	// If the seed is empty, we set it to nil to avoid confusion.
	// This is useful for cases where the seed is not used, and the OPRF client key is provided directly.
	if len(seed) != c.Hash.Size() {
		if len(seed) != 0 {
			return nil, ErrServerKeyMaterial.Join(internal.ErrInvalidOPRFSeedLength)
		}

		seed = nil
	}

	return &ServerKeyMaterial{
		Identity:       slices.Clone(id),
		PrivateKey:     sk,
		PublicKeyBytes: slices.Clone(pkBytes),
		OPRFGlobalSeed: slices.Clone(seed),
	}, nil
}

// skmStructureCheck checks the structure of the server key material data given the internal length headers.
func (c *Configuration) skmStructureCheck(data []byte) error {
	if len(data) < 9 {
		return internal.ErrInvalidEncodingLength
	}

	g := Group(data[0])
	if !g.Available() {
		return internal.ErrInvalidGroupEncoding
	}

	if g.Group() != c.AKE.Group() {
		return internal.ErrWrongGroup
	}

	// calculate minimal length given the group, when the private key is not set and seed and identity lengths are 0
	// 1 byte for group, 2 bytes for sk length, 2 bytes for pk length, public key length, 2 bytes for seed length,
	// 2 bytes for id length.
	minLength := 1 + 2 + 2 + g.Group().ElementLength() + 2 + 2
	if len(data) < minLength {
		return internal.ErrInvalidEncodingLength
	}

	skh := encoding.OS2IP(data[1:3]) // sk

	if g.Group().ScalarLength() != skh {
		return errors.Join(internal.ErrInvalidPrivateKey, internal.ErrInvalidScalar, internal.ErrInvalidEncodingLength)
	}

	// The following is never triggered due to the structure check and failsafe above, but is kept for safety.
	// The earlier minLength check guarantees len(data) ≥ elementLen+9, and for every configured curve
	// elementLen+9 ≥ 5+scalarLen = offset+2, so len(data) < offset+2 can never fire.
	offset := 3 + skh
	if len(data) < offset+2 {
		return errors.Join(
			internal.ErrInvalidServerPublicKey,
			internal.ErrInvalidElement,
			internal.ErrInvalidEncodingLength,
		)
	}

	pkh := encoding.OS2IP(data[offset : offset+2]) // pk

	if g.Group().ElementLength() != pkh {
		return errors.Join(
			internal.ErrInvalidServerPublicKey,
			internal.ErrInvalidElement,
			internal.ErrInvalidEncodingLength,
		)
	}

	offset += 2
	if len(data) < offset+pkh {
		return errors.Join(
			internal.ErrInvalidServerPublicKey,
			internal.ErrInvalidElement,
			internal.ErrInvalidEncodingLength,
		)
	}

	offset += pkh
	if len(data) < offset+2 {
		return internal.ErrInvalidEncodingLength
	}

	sh := encoding.OS2IP(data[offset : offset+2]) // seed
	if sh != 0 {
		if c.Hash.Size() != sh {
			return internal.ErrInvalidOPRFSeedLength
		}

		if len(data) < offset+2+sh {
			return internal.ErrInvalidOPRFSeedLength
		}
	}

	offset += 2 + sh
	if len(data) < offset+2 {
		return internal.ErrInvalidEncodingLength
	}

	idh := encoding.OS2IP(data[offset : offset+2]) // id
	offset += 2

	if len(data) != offset+idh {
		return internal.ErrInvalidEncodingLength
	}

	return nil
}

// DecodeServerKeyMaterialHex decodes the server key material from a hex string.
func (c *Configuration) DecodeServerKeyMaterialHex(data string) (*ServerKeyMaterial, error) {
	if data == "" {
		return nil, ErrServerKeyMaterial.Join(internal.ErrDecodingEmptyHex)
	}

	decoded, err := hex.DecodeString(data)
	if err != nil {
		return nil, ErrServerKeyMaterial.Join(err)
	}

	return c.DecodeServerKeyMaterial(decoded)
}
