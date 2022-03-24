// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

const (
	// NonceLength is the default length used for nonces.
	NonceLength = 32

	// SeedLength is the default length used for seeds.
	SeedLength = 32
)

var (
	errInvalidMessageLength = errors.New("invalid message length for the configuration")
	errInvalidBlindedData   = errors.New("blinded data is an invalid point")
	errInvalidClientEPK     = errors.New("invalid ephemeral client public key")
	errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
	errInvalidServerEPK     = errors.New("invalid ephemeral server public key")
	errInvalidServerPK      = errors.New("invalid server public key")
	errInvalidClientPK      = errors.New("invalid client public key")
)

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	r := make([]byte, length)
	if _, err := cryptorand.Read(r); err != nil {
		// We can as well not panic and try again in a loop and a counter to stop.
		panic(fmt.Errorf("unexpected error in generating random bytes : %w", err))
	}

	return r
}

// Configuration is the internal representation of the instance runtime parameters.
type Configuration struct {
	KDF             *KDF
	MAC             *Mac
	Hash            *Hash
	KSF             *KSF
	NonceLen        int
	EnvelopeSize    int
	OPRFPointLength int
	AkePointLength  int
	Group           group.Group
	OPRF            oprf.Ciphersuite
	Context         []byte
}

// DeserializeRegistrationRequest takes a serialized RegistrationRequest message as input and attempts to
// deserialize it.
func (c *Configuration) DeserializeRegistrationRequest(input []byte) (*message.RegistrationRequest, error) {
	if len(input) != c.OPRFPointLength {
		return nil, errInvalidMessageLength
	}

	blindedMessage, err := c.OPRF.Group().NewElement().Decode(input[:c.OPRFPointLength])
	if err != nil {
		return nil, errInvalidBlindedData
	}

	if blindedMessage.IsIdentity() {
		return nil, errInvalidBlindedData
	}

	return &message.RegistrationRequest{C: c.OPRF, BlindedMessage: blindedMessage}, nil
}

// DeserializeRegistrationResponse takes a serialized RegistrationResponse message as input and attempts to
// deserialize it.
func (c *Configuration) DeserializeRegistrationResponse(input []byte) (*message.RegistrationResponse, error) {
	if len(input) != c.OPRFPointLength+c.AkePointLength {
		return nil, errInvalidMessageLength
	}

	evaluatedMessage, err := c.OPRF.Group().NewElement().Decode(input[:c.OPRFPointLength])
	if err != nil {
		return nil, errInvalidEvaluatedData
	}

	if evaluatedMessage.IsIdentity() {
		return nil, errInvalidEvaluatedData
	}

	pks, err := c.Group.NewElement().Decode(input[c.OPRFPointLength:])
	if err != nil {
		return nil, errInvalidServerPK
	}

	if pks.IsIdentity() {
		return nil, errInvalidServerPK
	}

	return &message.RegistrationResponse{
		C:                c.OPRF,
		G:                c.Group,
		EvaluatedMessage: evaluatedMessage,
		Pks:              pks,
	}, nil
}

// DeserializeRegistrationRecord takes a serialized RegistrationRecord message as input and attempts to
// deserialize it.
func (c *Configuration) DeserializeRegistrationRecord(input []byte) (*message.RegistrationRecord, error) {
	if len(input) != c.AkePointLength+c.Hash.Size()+c.EnvelopeSize {
		return nil, errInvalidMessageLength
	}

	pk := input[:c.AkePointLength]
	maskingKey := input[c.AkePointLength : c.AkePointLength+c.Hash.Size()]
	env := input[c.AkePointLength+c.Hash.Size():]

	pku, err := c.Group.NewElement().Decode(pk)
	if err != nil {
		return nil, errInvalidClientPK
	}

	if pku.IsIdentity() {
		return nil, errInvalidClientPK
	}

	return &message.RegistrationRecord{
		G:          c.Group,
		PublicKey:  pku,
		MaskingKey: maskingKey,
		Envelope:   env,
	}, nil
}

func (c *Configuration) deserializeCredentialResponse(
	input []byte,
	maxResponseLength int,
) (*cred.CredentialResponse, error) {
	data, err := c.Group.NewElement().Decode(input[:c.OPRFPointLength])
	if err != nil {
		return nil, errInvalidEvaluatedData
	}

	if data.IsIdentity() {
		return nil, errInvalidEvaluatedData
	}

	return &cred.CredentialResponse{
		C:                c.OPRF,
		EvaluatedMessage: data,
		MaskingNonce:     input[c.OPRFPointLength : c.OPRFPointLength+c.NonceLen],
		MaskedResponse:   input[c.OPRFPointLength+c.NonceLen : maxResponseLength],
	}, nil
}

// DeserializeKE1 takes a serialized KE1 message as input and attempts to deserialize it.
func (c *Configuration) DeserializeKE1(input []byte) (*message.KE1, error) {
	if len(input) != c.OPRFPointLength+c.NonceLen+c.AkePointLength {
		return nil, errInvalidMessageLength
	}

	blindedMessage, err := c.Group.NewElement().Decode(input[:c.OPRFPointLength])
	if err != nil {
		return nil, errInvalidBlindedData
	}

	if blindedMessage.IsIdentity() {
		return nil, errInvalidBlindedData
	}

	nonceU := input[c.OPRFPointLength : c.OPRFPointLength+c.NonceLen]

	epku, err := c.Group.NewElement().Decode(input[c.OPRFPointLength+c.NonceLen:])
	if err != nil {
		return nil, errInvalidClientEPK
	}

	if epku.IsIdentity() {
		return nil, errInvalidClientEPK
	}

	return &message.KE1{
		CredentialRequest: &cred.CredentialRequest{
			C:              c.OPRF,
			BlindedMessage: blindedMessage,
		},
		NonceU: nonceU,
		EpkU:   epku,
	}, nil
}

// DeserializeKE2 takes a serialized KE2 message as input and attempts to deserialize it.
func (c *Configuration) DeserializeKE2(input []byte) (*message.KE2, error) {
	// size of credential response
	maxResponseLength := c.OPRFPointLength + c.NonceLen + c.AkePointLength + c.EnvelopeSize

	// Verify it matches the size of a legal KE2 message.
	if len(input) != maxResponseLength+c.NonceLen+c.AkePointLength+c.MAC.Size() {
		return nil, errInvalidMessageLength
	}

	cresp, err := c.deserializeCredentialResponse(input, maxResponseLength)
	if err != nil {
		return nil, err
	}

	nonceS := input[maxResponseLength : maxResponseLength+c.NonceLen]
	offset := maxResponseLength + c.NonceLen
	epk := input[offset : offset+c.AkePointLength]
	offset += c.AkePointLength
	mac := input[offset:]

	epks, err := c.Group.NewElement().Decode(epk)
	if err != nil {
		return nil, errInvalidServerEPK
	}

	if epks.IsIdentity() {
		return nil, errInvalidServerEPK
	}

	return &message.KE2{
		CredentialResponse: cresp,
		NonceS:             nonceS,
		EpkS:               epks,
		Mac:                mac,
	}, nil
}

// DeserializeKE3 takes a serialized KE3 message as input and attempts to deserialize it.
func (c *Configuration) DeserializeKE3(input []byte) (*message.KE3, error) {
	if len(input) != c.MAC.Size() {
		return nil, errInvalidMessageLength
	}

	return &message.KE3{Mac: input}, nil
}

// XorResponse is used to encrypt and decrypt the response in KE2.
func (c *Configuration) XorResponse(key, nonce, in []byte) []byte {
	pad := c.KDF.Expand(
		key,
		encoding.SuffixString(nonce, tag.CredentialResponsePad),
		encoding.PointLength[c.Group]+c.EnvelopeSize,
	)

	return Xor(pad, in)
}
