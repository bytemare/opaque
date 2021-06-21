// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

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
	return ake.KeyGen(s.AKEGroup)
}

func (s *Server) evaluate(seed, blinded []byte) (m []byte, err error) {
	oprf, err := s.OprfCiphersuite.Server(nil)
	if err != nil {
		return nil, fmt.Errorf("oprf server setup: %w", err)
	}

	ku := oprf.HashToScalar(seed)

	oprf, err = s.OprfCiphersuite.Server(ku.Bytes())
	if err != nil {
		return nil, fmt.Errorf("oprf server setup with key: %w", err)
	}

	evaluation, err := oprf.Evaluate(blinded)
	if err != nil {
		return nil, fmt.Errorf("oprf evaluation: %w", err)
	}

	return evaluation.Elements[0], nil
}

func (s *Server) oprfResponse(oprfSeed, credentialIdentifier, element []byte) (m []byte, err error) {
	seed := s.KDF.Expand(oprfSeed, encoding.Concat(credentialIdentifier, internal.OprfKey), encoding.ScalarLength[s.OprfCiphersuite.Group()])
	return s.evaluate(seed, element)
}

// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given identifiers.
func (s *Server) RegistrationResponse(req *message.RegistrationRequest,
	serverPublicKey, credentialIdentifier, oprfSeed []byte) (*message.RegistrationResponse, error) {
	z, err := s.oprfResponse(oprfSeed, credentialIdentifier, req.Data)
	if err != nil {
		return nil, fmt.Errorf(" RegistrationResponse: %w", err)
	}

	return &message.RegistrationResponse{
		Data: encoding.PadPoint(z, s.OprfCiphersuite.Group()),
		Pks:  serverPublicKey,
	}, nil
}

func (s *Server) credentialResponse(req *cred.CredentialRequest, serverPublicKey []byte, record *message.RegistrationUpload,
	credentialIdentifier, oprfSeed, maskingNonce []byte) (*cred.CredentialResponse, error) {
	z, err := s.oprfResponse(oprfSeed, credentialIdentifier, req.Data)
	if err != nil {
		return nil, fmt.Errorf("oprfResponse: %w", err)
	}

	// testing: integrated to support testing, to force values.
	if len(maskingNonce) == 0 {
		maskingNonce = utils.RandomBytes(s.Parameters.NonceLen)
	}

	clear := encoding.Concat(serverPublicKey, string(record.Envelope))
	maskedResponse := s.MaskResponse(record.MaskingKey, maskingNonce, clear)

	return &cred.CredentialResponse{
		Data:           encoding.PadPoint(z, s.OprfCiphersuite.Group()),
		MaskingNonce:   maskingNonce,
		MaskedResponse: maskedResponse,
	}, nil
}

// Init responds to a KE1 message with a KE2 message given server credentials and client record.
func (s *Server) Init(ke1 *message.KE1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed []byte,
	record *ClientRecord) (*message.KE2, error) {
	if serverPublicKey == nil {
		panic(nil)
	}

	response, err := s.credentialResponse(ke1.CredentialRequest, serverPublicKey,
		record.RegistrationUpload, record.CredentialIdentifier, oprfSeed, record.TestMaskNonce)
	if err != nil {
		return nil, fmt.Errorf(" credentialResponse: %w", err)
	}

	clientIdentity := record.ClientIdentity

	if clientIdentity == nil {
		clientIdentity = record.PublicKey
	}

	if serverIdentity == nil {
		serverIdentity = serverPublicKey
	}

	ke2, err := s.Ake.Response(s.Parameters, serverIdentity, serverSecretKey, clientIdentity, record.PublicKey, ke1, response)
	if err != nil {
		return nil, fmt.Errorf(" AKE response: %w", err)
	}

	return ke2, nil
}

// FakeCredentials allows a server to prevent client enumeration by sending back a faked response.
func (s *Server) FakeCredentials(ke1 *message.KE1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed []byte,
	record *ClientRecord) (*message.KE2, error) {
	return s.Init(ke1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed, record)
}

// Finish returns an error if the KE3 received from the client holds an invalid mac, and nil if correct.
func (s *Server) Finish(ke3 *message.KE3) error {
	if !s.Ake.Finalize(s.Parameters, ke3) {
		return errAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the session key if the previous calls to Init() and Finish() were
// successful.
func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}
