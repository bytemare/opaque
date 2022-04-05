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
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// ErrInvalidServerSecretKey indicates that server's secret key is invalid.
	ErrInvalidServerSecretKey = errors.New("invalid server secret key")

	// ErrAkeInvalidClientMac indicates that the MAC contained in the KE3 message is not valid in the given session.
	ErrAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

	// ErrInvalidState indicates that the given state is not valid due to a wrong length.
	ErrInvalidState = errors.New("invalid state length")

	// ErrInvalidEnvelopeLength indicates the envelope contained in the record is of invalid length.
	ErrInvalidEnvelopeLength = errors.New("record has invalid envelope length")

	// ErrInvalidPksLength indicates the input public key is not of right length.
	ErrInvalidPksLength = errors.New("input server public key's length is invalid")

	// ErrInvalidOPRFSeedLength indicates that the OPRF seed is not of right length.
	ErrInvalidOPRFSeedLength = errors.New("input OPRF seed length is invalid (must be of hash output length)")

	// ErrZeroSKS indicates that the server's private key is a zero scalar.
	ErrZeroSKS = errors.New("server private key is zero")
)

// Server represents an OPAQUE Server, exposing its functions and holding its state.
type Server struct {
	Deserialize *Deserializer
	conf        *internal.Configuration
	Ake         *ake.Server
}

// NewServer returns a Server instantiation given the application Configuration.
func NewServer(c *Configuration) (*Server, error) {
	if c == nil {
		c = DefaultConfiguration()
	}

	conf, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	return &Server{
		Deserialize: &Deserializer{conf: conf},
		conf:        conf,
		Ake:         ake.NewServer(),
	}, nil
}

// GetConf return the internal configuration.
func (s *Server) GetConf() *internal.Configuration {
	return s.conf
}

func (s *Server) oprfResponse(element *group.Point, oprfSeed, credentialIdentifier []byte) *group.Point {
	seed := s.conf.KDF.Expand(
		oprfSeed,
		encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	)
	ku := s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair))

	return s.conf.OPRF.Evaluate(ku, element)
}

// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given
// identifiers.
func (s *Server) RegistrationResponse(
	req *message.RegistrationRequest,
	serverPublicKey *group.Point,
	credentialIdentifier, oprfSeed []byte,
) *message.RegistrationResponse {
	z := s.oprfResponse(req.BlindedMessage, oprfSeed, credentialIdentifier)

	return &message.RegistrationResponse{
		C:                s.conf.OPRF,
		G:                s.conf.Group,
		EvaluatedMessage: z,
		Pks:              serverPublicKey,
	}
}

func (s *Server) credentialResponse(
	req *message.CredentialRequest,
	serverPublicKey []byte,
	record *message.RegistrationRecord,
	credentialIdentifier, oprfSeed, maskingNonce []byte,
) *message.CredentialResponse {
	z := s.oprfResponse(req.BlindedMessage, oprfSeed, credentialIdentifier)

	maskingNonce, maskedResponse := masking.Mask(
		s.conf,
		maskingNonce,
		record.MaskingKey,
		serverPublicKey,
		record.Envelope,
	)

	return &message.CredentialResponse{
		C:                s.conf.OPRF,
		EvaluatedMessage: z,
		MaskingNonce:     maskingNonce,
		MaskedResponse:   maskedResponse,
	}
}

func (s *Server) verifyInitInput(
	serverSecretKey, serverPublicKey, oprfSeed []byte,
	record *ClientRecord,
) (*group.Scalar, error) {
	sks, err := s.conf.Group.NewScalar().Decode(serverSecretKey)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", ErrInvalidServerSecretKey, err)
	}

	if sks.IsZero() {
		return nil, ErrZeroSKS
	}

	if len(oprfSeed) != s.conf.Hash.Size() {
		return nil, ErrInvalidOPRFSeedLength
	}

	if len(serverPublicKey) != s.conf.AkePointLength {
		return nil, ErrInvalidPksLength
	}

	_, err = s.conf.Group.NewElement().Decode(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid server public key: %w", err)
	}

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return nil, ErrInvalidEnvelopeLength
	}

	// We've checked that the server's public key and the client's envelope are of correct length,
	// thus ensuring that the subsequent xor-ing input is the same length as the encryption pad.

	return sks, nil
}

// LoginInit responds to a KE1 message with a KE2 message given server credentials and client record.
func (s *Server) LoginInit(
	ke1 *message.KE1,
	serverIdentity, serverSecretKey, serverPublicKey, oprfSeed []byte,
	record *ClientRecord,
) (*message.KE2, error) {
	sks, err := s.verifyInitInput(serverSecretKey, serverPublicKey, oprfSeed, record)
	if err != nil {
		return nil, err
	}

	response := s.credentialResponse(ke1.CredentialRequest, serverPublicKey,
		record.RegistrationRecord, record.CredentialIdentifier, oprfSeed, record.TestMaskNonce)

	clientIdentity := record.ClientIdentity

	if clientIdentity == nil {
		clientIdentity = encoding.SerializePoint(record.PublicKey, s.conf.Group)
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKey
	}

	ke2 := s.Ake.Response(s.conf, serverIdentity, sks, clientIdentity, record.PublicKey, ke1, response)

	return ke2, nil
}

// LoginFinish returns an error if the KE3 received from the client holds an invalid mac, and nil if correct.
func (s *Server) LoginFinish(ke3 *message.KE3) error {
	if !s.Ake.Finalize(s.conf, ke3) {
		return ErrAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the session key if the previous call to LoginInit() was successful.
func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}

// ExpectedMAC returns the expected client MAC if the previous call to LoginInit() was successful.
func (s *Server) ExpectedMAC() []byte {
	return s.Ake.ExpectedMAC()
}

// SetAKEState sets the internal state of the AKE server from the given bytes.
func (s *Server) SetAKEState(state []byte) error {
	if len(state) != s.conf.MAC.Size()+s.conf.KDF.Size() {
		return ErrInvalidState
	}

	return s.Ake.SetState(state[:s.conf.MAC.Size()], state[s.conf.MAC.Size():])
}

// SerializeState returns the internal state of the AKE server serialized to bytes.
func (s *Server) SerializeState() []byte {
	return s.Ake.SerializeState()
}
