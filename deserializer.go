// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"

	"github.com/bytemare/crypto/group"
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

// Deserializer exposes the message deserialization functions.
type Deserializer struct {
	conf *internal.Configuration
}

// RegistrationRequest takes a serialized RegistrationRequest message and returns a deserialized
// RegistrationRequest structure.
func (d *Deserializer) RegistrationRequest(registrationRequest []byte) (*message.RegistrationRequest, error) {
	if len(registrationRequest) != d.conf.OPRFPointLength {
		return nil, errInvalidMessageLength
	}

	blindedMessage, err := d.conf.OPRF.Group().NewElement().Decode(registrationRequest[:d.conf.OPRFPointLength])
	if err != nil {
		return nil, errInvalidBlindedData
	}

	return &message.RegistrationRequest{C: d.conf.OPRF, BlindedMessage: blindedMessage}, nil
}

func (d *Deserializer) registrationResponseLength() int {
	return d.conf.OPRFPointLength + d.conf.AkePointLength
}

// RegistrationResponse takes a serialized RegistrationResponse message and returns a deserialized
// RegistrationResponse structure.
func (d *Deserializer) RegistrationResponse(registrationResponse []byte) (*message.RegistrationResponse, error) {
	if len(registrationResponse) != d.registrationResponseLength() {
		return nil, errInvalidMessageLength
	}

	evaluatedMessage, err := d.conf.OPRF.Group().
		NewElement().
		Decode(registrationResponse[:d.conf.OPRFPointLength])
	if err != nil {
		return nil, errInvalidEvaluatedData
	}

	pks, err := d.conf.Group.NewElement().Decode(registrationResponse[d.conf.OPRFPointLength:])
	if err != nil {
		return nil, errInvalidServerPK
	}

	return &message.RegistrationResponse{
		C:                d.conf.OPRF,
		G:                d.conf.Group,
		EvaluatedMessage: evaluatedMessage,
		Pks:              pks,
	}, nil
}

func (d *Deserializer) recordLength() int {
	return d.conf.AkePointLength + d.conf.Hash.Size() + d.conf.EnvelopeSize
}

// RegistrationRecord takes a serialized RegistrationRecord message and returns a deserialized
// RegistrationRecord structure.
func (d *Deserializer) RegistrationRecord(record []byte) (*message.RegistrationRecord, error) {
	if len(record) != d.recordLength() {
		return nil, errInvalidMessageLength
	}

	pk := record[:d.conf.AkePointLength]
	maskingKey := record[d.conf.AkePointLength : d.conf.AkePointLength+d.conf.Hash.Size()]
	env := record[d.conf.AkePointLength+d.conf.Hash.Size():]

	pku, err := d.conf.Group.NewElement().Decode(pk)
	if err != nil {
		return nil, errInvalidClientPK
	}

	return &message.RegistrationRecord{
		G:          d.conf.Group,
		PublicKey:  pku,
		MaskingKey: maskingKey,
		Envelope:   env,
	}, nil
}

func (d *Deserializer) deserializeCredentialRequest(input []byte) (*message.CredentialRequest, error) {
	blindedMessage, err := d.conf.OPRF.Group().NewElement().Decode(input[:d.conf.OPRFPointLength])
	if err != nil {
		return nil, errInvalidBlindedData
	}

	return message.NewCredentialRequest(d.conf.OPRF, blindedMessage), nil
}

func (d *Deserializer) deserializeCredentialResponse(
	input []byte,
	maxResponseLength int,
) (*message.CredentialResponse, error) {
	data, err := d.conf.OPRF.Group().NewElement().Decode(input[:d.conf.OPRFPointLength])
	if err != nil {
		return nil, errInvalidEvaluatedData
	}

	return message.NewCredentialResponse(d.conf.OPRF,
		data,
		input[d.conf.OPRFPointLength:d.conf.OPRFPointLength+d.conf.NonceLen],
		input[d.conf.OPRFPointLength+d.conf.NonceLen:maxResponseLength]), nil
}

func (d *Deserializer) ke1Length() int {
	return d.conf.OPRFPointLength + d.conf.NonceLen + d.conf.AkePointLength
}

// KE1 takes a serialized KE1 message and returns a deserialized KE1 structure.
func (d *Deserializer) KE1(ke1 []byte) (*message.KE1, error) {
	if len(ke1) != d.ke1Length() {
		return nil, errInvalidMessageLength
	}

	request, err := d.deserializeCredentialRequest(ke1)
	if err != nil {
		return nil, err
	}

	nonceU := ke1[d.conf.OPRFPointLength : d.conf.OPRFPointLength+d.conf.NonceLen]

	epku, err := d.conf.Group.NewElement().Decode(ke1[d.conf.OPRFPointLength+d.conf.NonceLen:])
	if err != nil {
		return nil, errInvalidClientEPK
	}

	return &message.KE1{
		G:                 d.conf.Group,
		CredentialRequest: request,
		NonceU:            nonceU,
		EpkU:              epku,
	}, nil
}

func (d *Deserializer) ke2LengthWithoutCreds() int {
	return d.conf.NonceLen + d.conf.AkePointLength + d.conf.MAC.Size()
}

func (d *Deserializer) credentialResponseLength() int {
	return d.conf.OPRFPointLength + d.conf.NonceLen + d.conf.AkePointLength + d.conf.EnvelopeSize
}

// KE2 takes a serialized KE2 message and returns a deserialized KE2 structure.
func (d *Deserializer) KE2(ke2 []byte) (*message.KE2, error) {
	// size of credential response
	maxResponseLength := d.credentialResponseLength()

	// Verify it matches the size of a legal KE2
	if len(ke2) != maxResponseLength+d.ke2LengthWithoutCreds() {
		return nil, errInvalidMessageLength
	}

	cresp, err := d.deserializeCredentialResponse(ke2, maxResponseLength)
	if err != nil {
		return nil, err
	}

	nonceS := ke2[maxResponseLength : maxResponseLength+d.conf.NonceLen]
	offset := maxResponseLength + d.conf.NonceLen
	epk := ke2[offset : offset+d.conf.AkePointLength]
	offset += d.conf.AkePointLength
	mac := ke2[offset:]

	epks, err := d.conf.Group.NewElement().Decode(epk)
	if err != nil {
		return nil, errInvalidServerEPK
	}

	return &message.KE2{
		G:                  d.conf.Group,
		CredentialResponse: cresp,
		NonceS:             nonceS,
		EpkS:               epks,
		Mac:                mac,
	}, nil
}

// KE3 takes a serialized KE3 message and returns a deserialized KE3 structure.
func (d *Deserializer) KE3(ke3 []byte) (*message.KE3, error) {
	if len(ke3) != d.conf.MAC.Size() {
		return nil, errInvalidMessageLength
	}

	return &message.KE3{Mac: ke3}, nil
}

// DecodeAkePrivateKey takes a serialized private key (a scalar) and attempts to return it's decoded form.
func (d *Deserializer) DecodeAkePrivateKey(encoded []byte) (*group.Scalar, error) {
	return d.conf.Group.NewScalar().Decode(encoded)
}

// DecodeAkePublicKey takes a serialized public key (a point) and attempts to return it's decoded form.
func (d *Deserializer) DecodeAkePublicKey(encoded []byte) (*group.Point, error) {
	return d.conf.Group.NewElement().Decode(encoded)
}
