// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

// Deserializer exposes the message deserialization methods.
type Deserializer struct {
	conf *internal.Configuration
}

// RegistrationRequest takes a serialized RegistrationRequest message and returns a deserialized
// RegistrationRequest structure.
func (d *Deserializer) RegistrationRequest(registrationRequest []byte) (*message.RegistrationRequest, error) {
	if len(registrationRequest) != d.conf.OPRF.Group().ElementLength() {
		return nil, ErrInvalidMessageLength
	}

	blindedMessage := d.conf.OPRF.Group().NewElement()

	err := blindedMessage.Decode(registrationRequest[:d.conf.OPRF.Group().ElementLength()])
	if err != nil || blindedMessage.IsIdentity() {
		return nil, ErrInvalidBlindedData
	}

	return &message.RegistrationRequest{BlindedMessage: blindedMessage}, nil
}

// RegistrationResponse takes a serialized RegistrationResponse message and returns a deserialized
// RegistrationResponse structure.
func (d *Deserializer) RegistrationResponse(registrationResponse []byte) (*message.RegistrationResponse, error) {
	if len(registrationResponse) != d.registrationResponseLength() {
		return nil, ErrInvalidMessageLength
	}

	evaluatedMessage := d.conf.OPRF.Group().NewElement()

	err := evaluatedMessage.Decode(registrationResponse[:d.conf.OPRF.Group().ElementLength()])
	if err != nil || evaluatedMessage.IsIdentity() {
		return nil, ErrInvalidEvaluatedData
	}

	pksBytes := registrationResponse[d.conf.OPRF.Group().ElementLength():]

	pks := d.conf.Group.NewElement()
	if err = pks.Decode(pksBytes); err != nil || pks.IsIdentity() {
		return nil, ErrInvalidServerPK
	}

	return &message.RegistrationResponse{
		EvaluatedMessage: evaluatedMessage,
		ServerPublicKey:  pksBytes,
	}, nil
}

// RegistrationRecord takes a serialized RegistrationRecord message and returns a deserialized
// RegistrationRecord structure.
func (d *Deserializer) RegistrationRecord(record []byte) (*message.RegistrationRecord, error) {
	if len(record) != d.recordLength() {
		return nil, ErrInvalidMessageLength
	}

	pk := record[:d.conf.Group.ElementLength()]
	maskingKey := record[d.conf.Group.ElementLength() : d.conf.Group.ElementLength()+d.conf.Hash.Size()]
	env := record[d.conf.Group.ElementLength()+d.conf.Hash.Size():]

	pku := d.conf.Group.NewElement()
	if err := pku.Decode(pk); err != nil || pku.IsIdentity() {
		return nil, ErrInvalidClientPK
	}

	return &message.RegistrationRecord{
		ClientPublicKey: pku,
		MaskingKey:      maskingKey,
		Envelope:        env,
	}, nil
}

// KE1 takes a serialized KE1 message and returns a deserialized KE1 structure.
func (d *Deserializer) KE1(ke1 []byte) (*message.KE1, error) {
	if len(ke1) != d.ke1Length() {
		return nil, ErrInvalidMessageLength
	}

	request, err := d.deserializeCredentialRequest(ke1)
	if err != nil {
		return nil, err
	}

	nonceU := ke1[d.conf.OPRF.Group().ElementLength() : d.conf.OPRF.Group().ElementLength()+d.conf.NonceLen]

	epku := d.conf.Group.NewElement()
	if err = epku.Decode(ke1[d.conf.OPRF.Group().ElementLength()+d.conf.NonceLen:]); err != nil || epku.IsIdentity() {
		return nil, ErrInvalidClientEPK
	}

	return &message.KE1{
		CredentialRequest:    request,
		ClientNonce:          nonceU,
		ClientPublicKeyshare: epku,
	}, nil
}

// KE2 takes a serialized KE2 message and returns a deserialized KE2 structure.
func (d *Deserializer) KE2(ke2 []byte) (*message.KE2, error) {
	// size of credential response
	maxResponseLength := d.credentialResponseLength()

	// Verify it matches the size of a legal KE2
	if len(ke2) != maxResponseLength+d.ke2LengthWithoutCreds() {
		return nil, ErrInvalidMessageLength
	}

	cresp, err := d.deserializeCredentialResponse(ke2, maxResponseLength)
	if err != nil {
		return nil, err
	}

	nonceS := ke2[maxResponseLength : maxResponseLength+d.conf.NonceLen]
	offset := maxResponseLength + d.conf.NonceLen
	epk := ke2[offset : offset+d.conf.Group.ElementLength()]
	offset += d.conf.Group.ElementLength()
	mac := ke2[offset:]

	epks := d.conf.Group.NewElement()
	if err = epks.Decode(epk); err != nil || epks.IsIdentity() {
		return nil, ErrInvalidServerEPK
	}

	return &message.KE2{
		CredentialResponse:   cresp,
		ServerNonce:          nonceS,
		ServerPublicKeyshare: epks,
		ServerMac:            mac,
	}, nil
}

// KE3 takes a serialized KE3 message and returns a deserialized KE3 structure.
func (d *Deserializer) KE3(ke3 []byte) (*message.KE3, error) {
	if len(ke3) != d.conf.MAC.Size() {
		return nil, ErrInvalidMessageLength
	}

	return &message.KE3{ClientMac: ke3}, nil
}

// DecodePrivateKey takes a serialized private key (a scalar) and attempts to return it's decoded form.
func (d *Deserializer) DecodePrivateKey(encoded []byte) (*ecc.Scalar, error) {
	sk := d.conf.Group.NewScalar()
	if err := sk.Decode(encoded); err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	if sk.IsZero() {
		return nil, fmt.Errorf("invalid private key: %w", ErrPrivateKeyZero)
	}

	return sk, nil
}

// DecodePublicKey takes a serialized public key (a point) and attempts to return it's decoded form.
func (d *Deserializer) DecodePublicKey(encoded []byte) (*ecc.Element, error) {
	pk := d.conf.Group.NewElement()
	if err := pk.Decode(encoded); err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	if pk.IsIdentity() {
		return nil, fmt.Errorf("invalid public key: %w", ErrPublicKeyIdentity)
	}

	return pk, nil
}

func (d *Deserializer) registrationResponseLength() int {
	return d.conf.OPRF.Group().ElementLength() + d.conf.Group.ElementLength()
}

func (d *Deserializer) recordLength() int {
	return d.conf.Group.ElementLength() + d.conf.Hash.Size() + d.conf.EnvelopeSize
}

func (d *Deserializer) deserializeCredentialRequest(input []byte) (*message.CredentialRequest, error) {
	blindedMessage := d.conf.OPRF.Group().NewElement()

	err := blindedMessage.Decode(input[:d.conf.OPRF.Group().ElementLength()])
	if err != nil || blindedMessage.IsIdentity() {
		return nil, ErrInvalidBlindedData
	}

	return message.NewCredentialRequest(blindedMessage), nil
}

func (d *Deserializer) deserializeCredentialResponse(
	input []byte,
	maxResponseLength int,
) (*message.CredentialResponse, error) {
	evaluatedOPRF := d.conf.OPRF.Group().NewElement()

	err := evaluatedOPRF.Decode(input[:d.conf.OPRF.Group().ElementLength()])
	if err != nil || evaluatedOPRF.IsIdentity() {
		return nil, ErrInvalidEvaluatedData
	}

	return message.NewCredentialResponse(evaluatedOPRF,
		input[d.conf.OPRF.Group().ElementLength():d.conf.OPRF.Group().ElementLength()+d.conf.NonceLen],
		input[d.conf.OPRF.Group().ElementLength()+d.conf.NonceLen:maxResponseLength]), nil
}

func (d *Deserializer) ke1Length() int {
	return d.conf.OPRF.Group().ElementLength() + d.conf.NonceLen + d.conf.Group.ElementLength()
}

func (d *Deserializer) ke2LengthWithoutCreds() int {
	return d.conf.NonceLen + d.conf.Group.ElementLength() + d.conf.MAC.Size()
}

func (d *Deserializer) credentialResponseLength() int {
	return d.conf.OPRF.Group().ElementLength() + d.conf.NonceLen + d.conf.Group.ElementLength() + d.conf.EnvelopeSize
}
