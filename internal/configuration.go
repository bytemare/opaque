// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/voprf"

	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var (
	errInvalidSize          = errors.New("invalid message size")
	errInvalidMessageLength = errors.New("invalid message length")
	errCredReqShort         = errors.New(" CredentialRequest too short")
	errInvalidCredRespShort = errors.New(" CredentialResponse too short")
	errShortMessage         = errors.New("message is too short")
)

type Parameters struct {
	KDF             *KDF
	MAC             *Mac
	Hash            *Hash
	MHF             *MHF
	NonceLen        int
	EnvelopeSize    int
	OPRFPointLength int
	AkePointLength  int
	OprfCiphersuite voprf.Ciphersuite
	AKEGroup        ciphersuite.Identifier
	Context         []byte
}

func (p *Parameters) DeserializeRegistrationRequest(input []byte) (*message.RegistrationRequest, error) {
	if len(input) != p.OPRFPointLength {
		return nil, errInvalidSize
	}

	return &message.RegistrationRequest{Data: input}, nil
}

func (p *Parameters) DeserializeRegistrationResponse(input []byte) (*message.RegistrationResponse, error) {
	if len(input) != p.OPRFPointLength+p.AkePointLength {
		return nil, errInvalidSize
	}

	return &message.RegistrationResponse{
		Data: input[:p.OPRFPointLength],
		Pks:  input[p.OPRFPointLength:],
	}, nil
}

func (p *Parameters) DeserializeRegistrationUpload(input []byte) (*message.RegistrationUpload, error) {
	if len(input) != p.AkePointLength+p.Hash.Size()+p.EnvelopeSize {
		return nil, errInvalidMessageLength
	}

	pku := input[:p.AkePointLength]
	maskingKey := input[p.AkePointLength : p.AkePointLength+p.Hash.Size()]
	env := input[p.AkePointLength+p.Hash.Size():]

	return &message.RegistrationUpload{
		PublicKey:  pku,
		MaskingKey: maskingKey,
		Envelope:   env,
	}, nil
}

func (p *Parameters) DeserializeCredentialRequest(input []byte) (*cred.CredentialRequest, error) {
	if len(input) != p.OPRFPointLength {
		return nil, errCredReqShort
	}

	return &cred.CredentialRequest{Data: input[:p.OPRFPointLength]}, nil
}

func (p *Parameters) deserializeCredentialResponse(input []byte) (*cred.CredentialResponse, int, error) {
	supposedLength := p.OPRFPointLength + p.NonceLen + p.AkePointLength + p.EnvelopeSize
	if len(input) < supposedLength {
		return nil, 0, errInvalidCredRespShort
	}

	return &cred.CredentialResponse{
		Data:           input[:p.OPRFPointLength],
		MaskingNonce:   input[p.OPRFPointLength : p.OPRFPointLength+p.NonceLen],
		MaskedResponse: input[p.OPRFPointLength+p.NonceLen : supposedLength],
	}, supposedLength, nil
}

func (p *Parameters) DeserializeCredentialResponse(input []byte) (*cred.CredentialResponse, error) {
	c, _, err := p.deserializeCredentialResponse(input)
	return c, err
}

func (p *Parameters) DeserializeKE1(input []byte) (*message.KE1, error) {
	if len(input) != p.OPRFPointLength+p.NonceLen+p.AkePointLength {
		return nil, errInvalidSize
	}

	creq, err := p.DeserializeCredentialRequest(input[:p.OPRFPointLength])
	if err != nil {
		return nil, fmt.Errorf("deserializing the credential crequest: %w", err)
	}

	nonceU := input[p.OPRFPointLength : p.OPRFPointLength+p.NonceLen]

	return &message.KE1{
		CredentialRequest: creq,
		NonceU:            nonceU,
		EpkU:              input[p.OPRFPointLength+p.NonceLen:],
	}, nil
}

func (p *Parameters) DeserializeKE2(input []byte) (*message.KE2, error) {
	if len(input) != p.OPRFPointLength+p.NonceLen+p.AkePointLength+p.EnvelopeSize+p.NonceLen+p.AkePointLength+p.MAC.Size() {
		return nil, errShortMessage
	}

	cresp, offset, err := p.deserializeCredentialResponse(input)
	if err != nil {
		return nil, fmt.Errorf("decoding credential response: %w", err)
	}

	nonceS := input[offset : offset+p.NonceLen]
	offset += p.NonceLen
	epks := input[offset : offset+p.AkePointLength]
	offset += p.AkePointLength
	mac := input[offset:]

	return &message.KE2{
		CredentialResponse: cresp,
		NonceS:             nonceS,
		EpkS:               epks,
		Mac:                mac,
	}, nil
}

func (p *Parameters) DeserializeKE3(input []byte) (*message.KE3, error) {
	if len(input) != p.MAC.Size() {
		return nil, errInvalidMessageLength
	}

	return &message.KE3{Mac: input}, nil
}

func (p *Parameters) MaskResponse(key, nonce, in []byte) []byte {
	pad := p.KDF.Expand(key, encoding.Concat(nonce, TagCredentialResponsePad), encoding.PointLength[p.AKEGroup]+p.EnvelopeSize)
	return Xor(pad, in)
}
