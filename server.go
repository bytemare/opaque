// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// ErrAkeInvalidClientMac indicates that the MAC contained in the KE3 message is not valid in the given session.
	ErrAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

	// ErrInvalidState indicates that the given state is not valid due to a wrong length.
	ErrInvalidState = errors.New("invalid state length")
)

// Server represents an OPAQUE Server, exposing its functions and holding its state.
type Server struct {
	*internal.Parameters
	Ake *ake.Server
}

// NewServer returns a Server instantiation given the application Configuration.
func NewServer(p *Configuration) *Server {
	if p == nil {
		p = DefaultConfiguration()
	}

	ip := p.toInternal()

	return &Server{
		Parameters: ip,
		Ake:        ake.NewServer(),
	}
}

// KeyGen returns a key pair in the AKE group.
func (s *Server) KeyGen() (secretKey, publicKey []byte) {
	return ake.KeyGen(s.Group)
}

func (s *Server) oprfResponse(element *group.Point, oprfSeed, credentialIdentifier, info []byte) *group.Point {
	seed := s.KDF.Expand(oprfSeed, encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF), internal.SeedLength)
	ku := s.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair))

	return s.OPRF.Evaluate(ku, element, info)
}

// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given identifiers.
func (s *Server) RegistrationResponse(req *message.RegistrationRequest,
	serverPublicKey *group.Point, credentialIdentifier, oprfSeed []byte) *message.RegistrationResponse {
	z := s.oprfResponse(req.Data, oprfSeed, credentialIdentifier, s.Info)

	return &message.RegistrationResponse{
		C:    s.OPRF,
		Data: z,
		Pks:  serverPublicKey,
	}
}

func (s *Server) credentialResponse(req *cred.CredentialRequest, serverPublicKey []byte, record *message.RegistrationRecord,
	credentialIdentifier, oprfSeed, maskingNonce, info []byte) *cred.CredentialResponse {
	z := s.oprfResponse(req.Data, oprfSeed, credentialIdentifier, info)

	// testing: integrated to support testing, to force values.
	if len(maskingNonce) == 0 {
		maskingNonce = internal.RandomBytes(s.Parameters.NonceLen)
	}

	clear := encoding.Concat(serverPublicKey, record.Envelope)
	maskedResponse := s.MaskResponse(record.MaskingKey, maskingNonce, clear)

	return &cred.CredentialResponse{
		Data:           z,
		MaskingNonce:   maskingNonce,
		MaskedResponse: maskedResponse,
	}
}

// Init responds to a KE1 message with a KE2 message given server credentials and client record.
func (s *Server) Init(ke1 *message.KE1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed []byte,
	record *ClientRecord) (*message.KE2, error) {
	sks, err := s.Group.NewScalar().Decode(serverSecretKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server secret key: %w", err)
	}

	_, err = s.Group.NewElement().Decode(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	pku, err := s.Group.NewElement().Decode(record.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid client public key in record: %w", err)
	}

	response := s.credentialResponse(ke1.CredentialRequest, serverPublicKey,
		record.RegistrationRecord, record.CredentialIdentifier, oprfSeed, record.TestMaskNonce, s.Info)

	clientIdentity := record.ClientIdentity

	if clientIdentity == nil {
		clientIdentity = record.PublicKey
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKey
	}

	ke2 := s.Ake.Response(s.Parameters, serverIdentity, sks, clientIdentity, pku, ke1, response)

	return ke2, nil
}

// Finish returns an error if the KE3 received from the client holds an invalid mac, and nil if correct.
func (s *Server) Finish(ke3 *message.KE3) error {
	if !s.Ake.Finalize(s.Parameters, ke3) {
		return ErrAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the session key if the previous call to Init() was successful.
func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}

// ExpectedMAC returns the expected client MAC if the previous call to Init() was successful.
func (s *Server) ExpectedMAC() []byte {
	return s.Ake.ExpectedMAC()
}

// DeserializeRegistrationRequest takes a serialized RegistrationRequest message and returns a deserialized RegistrationRequest structure.
func (s *Server) DeserializeRegistrationRequest(registrationRequest []byte) (*message.RegistrationRequest, error) {
	return s.Parameters.DeserializeRegistrationRequest(registrationRequest)
}

// DeserializeRegistrationResponse takes a serialized RegistrationResponse message and returns a deserialized RegistrationResponse structure.
func (s *Server) DeserializeRegistrationResponse(registrationResponse []byte) (*message.RegistrationResponse, error) {
	return s.Parameters.DeserializeRegistrationResponse(registrationResponse)
}

// DeserializeRegistrationRecord takes a serialized RegistrationRecord message and returns a deserialized RegistrationRecord structure.
func (s *Server) DeserializeRegistrationRecord(registrationUpload []byte) (*message.RegistrationRecord, error) {
	return s.Parameters.DeserializeRecord(registrationUpload)
}

// DeserializeKE1 takes a serialized KE1 message and returns a deserialized KE1 structure.
func (s *Server) DeserializeKE1(ke1 []byte) (*message.KE1, error) {
	return s.Parameters.DeserializeKE1(ke1)
}

// DeserializeKE2 takes a serialized KE2 message and returns a deserialized KE2 structure.
func (s *Server) DeserializeKE2(ke2 []byte) (*message.KE2, error) {
	return s.Parameters.DeserializeKE2(ke2)
}

// DeserializeKE3 takes a serialized KE3 message and returns a deserialized KE3 structure.
func (s *Server) DeserializeKE3(ke3 []byte) (*message.KE3, error) {
	return s.Parameters.DeserializeKE3(ke3)
}

// SetAKEState sets the internal state of the AKE server from the given bytes.
func (s *Server) SetAKEState(state []byte) error {
	if len(state) != s.MAC.Size()+s.KDF.Size() {
		return ErrInvalidState
	}

	return s.Ake.SetState(state[:s.MAC.Size()], state[s.MAC.Size():])
}

// SerializeState returns the internal state of the AKE server serialized to bytes.
func (s *Server) SerializeState() []byte {
	return s.Ake.SerializeState()
}
