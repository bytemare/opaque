// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"

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
		return nil, ErrRegistrationRequest.Join(internal.ErrInvalidMessageLength)
	}

	blindedMessage, err := DeserializeElement(d.conf.OPRF.Group(), registrationRequest)
	if err != nil {
		return nil, ErrRegistrationRequest.Join(internal.ErrInvalidBlindedMessage, err)
	}

	return &message.RegistrationRequest{BlindedMessage: blindedMessage}, nil
}

// RegistrationResponse takes a serialized RegistrationResponse message and returns a deserialized
// RegistrationResponse structure.
func (d *Deserializer) RegistrationResponse(registrationResponse []byte) (*message.RegistrationResponse, error) {
	if len(registrationResponse) != d.registrationResponseLength() {
		return nil, ErrRegistrationResponse.Join(internal.ErrInvalidMessageLength)
	}

	evaluatedMessage, err := DeserializeElement(d.conf.OPRF.Group(), registrationResponse)
	if err != nil {
		return nil, ErrRegistrationResponse.Join(internal.ErrInvalidEvaluatedMessage, err)
	}

	pksBytes := registrationResponse[d.conf.OPRF.Group().ElementLength():]

	_, err = DeserializeElement(d.conf.Group, pksBytes)
	if err != nil {
		return nil, ErrRegistrationResponse.Join(internal.ErrInvalidServerPublicKey, err)
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
		return nil, ErrRegistrationRecord.Join(internal.ErrInvalidMessageLength)
	}

	pk := record[:d.conf.Group.ElementLength()]
	maskingKey := record[d.conf.Group.ElementLength() : d.conf.Group.ElementLength()+d.conf.Hash.Size()]
	env := record[d.conf.Group.ElementLength()+d.conf.Hash.Size():]

	pku, err := DeserializeElement(d.conf.Group, pk)
	if err != nil {
		return nil, ErrRegistrationRecord.Join(internal.ErrInvalidClientPublicKey, err)
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
		return nil, ErrKE1.Join(internal.ErrInvalidMessageLength)
	}

	request, err := d.deserializeCredentialRequest(ke1)
	if err != nil {
		return nil, ErrKE1.Join(err)
	}

	nonceU := ke1[d.conf.OPRF.Group().ElementLength() : d.conf.OPRF.Group().ElementLength()+d.conf.NonceLen]

	epku, err := DeserializeElement(d.conf.Group, ke1[d.conf.OPRF.Group().ElementLength()+d.conf.NonceLen:])
	if err != nil {
		return nil, ErrKE1.Join(internal.ErrInvalidClientKeyShare, err)
	}

	return &message.KE1{
		CredentialRequest: *request,
		ClientNonce:       nonceU,
		ClientKeyShare:    epku,
	}, nil
}

// KE2 takes a serialized KE2 message and returns a deserialized KE2 structure.
func (d *Deserializer) KE2(ke2 []byte) (*message.KE2, error) {
	// size of credential response
	maxResponseLength := d.credentialResponseLength()

	// Verify it matches the size of a legal KE2
	if len(ke2) != maxResponseLength+d.ke2LengthWithoutCreds() {
		return nil, ErrKE2.Join(internal.ErrInvalidMessageLength)
	}

	cresp, err := d.deserializeCredentialResponse(ke2, maxResponseLength)
	if err != nil {
		return nil, ErrKE2.Join(err)
	}

	nonceS := ke2[maxResponseLength : maxResponseLength+d.conf.NonceLen]
	offset := maxResponseLength + d.conf.NonceLen
	epk := ke2[offset : offset+d.conf.Group.ElementLength()]
	offset += d.conf.Group.ElementLength()
	mac := ke2[offset:]

	epks, err := DeserializeElement(d.conf.Group, epk)
	if err != nil {
		return nil, ErrKE2.Join(internal.ErrInvalidServerKeyShare, err)
	}

	return &message.KE2{
		CredentialResponse: cresp,
		ServerNonce:        nonceS,
		ServerKeyShare:     epks,
		ServerMac:          mac,
	}, nil
}

// KE3 takes a serialized KE3 message and returns a deserialized KE3 structure.
func (d *Deserializer) KE3(ke3 []byte) (*message.KE3, error) {
	if len(ke3) != d.conf.MAC.Size() {
		return nil, ErrKE3.Join(internal.ErrInvalidMessageLength)
	}

	return &message.KE3{ClientMac: ke3}, nil
}

// DecodePrivateKey takes a serialized private key (a scalar) and attempts to return it's decoded form.
func (d *Deserializer) DecodePrivateKey(encoded []byte) (*ecc.Scalar, error) {
	sk := d.conf.Group.NewScalar()
	if err := sk.Decode(encoded); err != nil {
		return nil, errors.Join(internal.ErrInvalidPrivateKey, err)
	}

	if sk.IsZero() {
		return nil, internal.ErrPrivateKeyZero
	}

	return sk, nil
}

// DecodePublicKey takes a serialized public key (a point) and attempts to return it's decoded form.
func (d *Deserializer) DecodePublicKey(encoded []byte) (*ecc.Element, error) {
	pk, err := DeserializeElement(d.conf.Group, encoded)
	if err != nil {
		return nil, errors.Join(internal.ErrInvalidPublicKey, err)
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
	blindedMessage, err := DeserializeElement(d.conf.OPRF.Group(), input)
	if err != nil {
		return nil, errors.Join(internal.ErrInvalidBlindedMessage, err)
	}

	return message.NewCredentialRequest(blindedMessage), nil
}

func (d *Deserializer) deserializeCredentialResponse(
	input []byte,
	maxResponseLength int,
) (*message.CredentialResponse, error) {
	evaluatedMessage, err := DeserializeElement(d.conf.OPRF.Group(), input)
	if err != nil {
		return nil, errors.Join(internal.ErrInvalidBlindedMessage, err)
	}

	return message.NewCredentialResponse(evaluatedMessage,
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

// DeserializeElement takes a byte slice and attempts to decode it into an Element of the given group, and returns an
// error if the decoding fails or if the element is the identity element (point at infinity).
func DeserializeElement(g ecc.Group, input []byte) (*ecc.Element, error) {
	e := g.NewElement()

	err := e.Decode(input[:g.ElementLength()])
	if err != nil {
		return nil, err
	}

	if e.IsIdentity() {
		return nil, internal.ErrElementIdentity
	}

	return e, nil
}

// DeserializeScalar takes a byte slice and attempts to decode it into a Scalar of the given group, and returns an
// error if the decoding fails or if the scalar is zero.
func DeserializeScalar(g ecc.Group, input []byte) (*ecc.Scalar, error) {
	s := g.NewScalar()

	err := s.Decode(input[:g.ScalarLength()])
	if err != nil {
		return nil, err
	}

	if s.IsZero() {
		return nil, internal.ErrScalarZero
	}

	return s, nil
}
