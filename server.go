// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

// Server represents an OPAQUE Server, exposing its functions and holding its key material. The server is thread-safe
// and can be used concurrently by multiple goroutines to serve clients, given the same key material.
// The server's key material must be set before using the registration and login functions.
type Server struct {
	ServerKeyMaterial *ServerKeyMaterial
	Deserialize       *Deserializer
	conf              *internal.Configuration
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
		ServerKeyMaterial: nil,
		Deserialize:       &Deserializer{conf: conf},
		conf:              conf,
	}, nil
}

// SetKeyMaterial sets the server's key material. The ServerKeyMaterial must be set before calling RegistrationResponse
// or GenerateKE2. It validates the key material and returns an error if it is invalid.
func (s *Server) SetKeyMaterial(skm *ServerKeyMaterial) error {
	if err := s.validateKeyMaterial(skm); err != nil {
		return err
	}

	s.ServerKeyMaterial = skm

	return nil
}

// RegistrationResponse computes the server’s response to a client’s RegistrationRequest.
//
// It client-specific OPRF key on the client input and returns a RegistrationResponse message in response to the
// client's RegistrationRequest message req.
//
// Parameters:
//   - clientCredentialIdentifier: application-defined, stable identifier for this client. If clientOPRFKey is nil,
//     the OPRF key is derived from this identifier and the server’s global OPRF seed provided in the server key
//     material. The identifier MUST be unique per client and stable for the credential’s lifetime from registration to
//     all subsequent logins. It MUST NOT be empty if clientOPRFKey is nil.
//   - clientOPRFKey: optional explicit client OPRF secret key. If non-nil, it is used directly instead
//     of deriving it from the credentialIdentifier and globalOPRFSeed.
//
// Preconditions:
//   - s.SetKeyMaterial has been called. The server’s AKE public key (ServerKeyMaterial.PublicKeyBytes) is required
//     to populate the response.
//   - If clientOPRFKey is nil, the global OPRF seed (ServerKeyMaterial.OPRFGlobalSeed) MUST be set and have length
//     equal to Hash.Size().
//
// Security and usage notes:
//   - Using a single global OPRF seed together with unique clientCredentialIdentifier values prevents client
//     enumeration by deriving per-client OPRF keys.
//   - The clientCredentialIdentifier MUST be consistent across registration and subsequent logins for a given client.
//   - When the OPRF key is derived internally, it is zeroed after use.
func (s *Server) RegistrationResponse(
	req *message.RegistrationRequest,
	clientCredentialIdentifier []byte,
	clientOPRFKey *ecc.Scalar, // If set, this will be used as the client OPRF key directly instead
	// of deriving it from the credentialIdentifier and globalOPRFSeed.
) (*message.RegistrationResponse, error) {
	if len(s.ServerKeyMaterial.PublicKeyBytes) != s.conf.Group.ElementLength() {
		return nil, ErrServerKeyMaterial.Join(
			internal.ErrInvalidServerPublicKey,
			internal.ErrInvalidElement,
			internal.ErrInvalidEncodingLength,
		)
	}

	ku, err := s.chooseOPRFKey(clientCredentialIdentifier, clientOPRFKey)
	if err != nil {
		return nil, err
	}

	defer func() {
		// If the OPRF key was derived internally, we attempt to wipe it to avoid leaking the key.
		if clientOPRFKey == nil {
			internal.ClearScalar(&ku)
		}
	}()

	if err = s.verifyRegistrationRequest(req); err != nil {
		return nil, ErrRegistration.Join(err)
	}

	return &message.RegistrationResponse{
		EvaluatedMessage: s.conf.OPRF.Evaluate(ku, req.BlindedMessage),
		ServerPublicKey:  s.ServerKeyMaterial.PublicKeyBytes,
	}, nil
}

// GenerateKE2 responds to a KE1 message with a KE2 message a client record. The ServerKeyMaterial must be set before
// calling this method using SetKeyMaterial. This method can be used concurrently by multiple goroutines for different
// clients.
func (s *Server) GenerateKE2(
	ke1 *message.KE1,
	record *ClientRecord,
	options ...*ServerOptions,
) (*message.KE2, *ServerOutput, error) {
	if err := s.validateKE1(ke1); err != nil {
		return nil, nil, err
	}

	if err := s.validateKeyMaterial(s.ServerKeyMaterial); err != nil {
		return nil, nil, err
	}

	if err := s.verifyRecord(record); err != nil {
		return nil, nil, err
	}

	o := &serverOptions{
		ClientOPRFKey:  nil,
		MaskingNonce:   nil,
		SecretKeyShare: nil,
		AKENonce:       nil,
	}
	defer internal.ClearScalar(&o.ClientOPRFKey)
	defer internal.ClearScalar(&o.SecretKeyShare)

	err := s.parseOptions(o, options)
	if err != nil {
		return nil, nil, err
	}

	if len(o.AKENonce) == 0 {
		o.AKENonce = internal.RandomBytes(internal.NonceLength)
	}

	ku, err := s.chooseOPRFKey(record.CredentialIdentifier, o.ClientOPRFKey)
	if err != nil {
		return nil, nil, err
	}

	defer internal.ClearScalar(&ku)

	ke2, output := s.coreGenerateKE2(ke1, record, o, ku)

	return ke2, output, nil
}

// LoginFinish verifies whether the KE3 message holds the client MAC that matches expectedClientMac. If this method
// returns an error, the session secret must not be used. If it returns nil, the session secret can be used.
func (s *Server) LoginFinish(ke3 *message.KE3, expectedClientMac []byte) error {
	if ke3 == nil {
		return ErrKE3.Join(internal.ErrKE3Nil)
	}

	if ok := ake.VerifyClientMac(s.conf, ke3, expectedClientMac); !ok {
		return ErrAuthentication.Join(internal.ErrClientAuthentication, internal.ErrInvalidClientMac)
	}

	return nil
}

// ServerOutput is the result of a successful GenerateKE2 call, containing the client MAC and session secret. The
// SessionSecret must not be used before the client's KE3 message has been verified against the ClientMAC.
type ServerOutput struct {
	ClientMAC     []byte
	SessionSecret []byte
}

func (s *Server) coreGenerateKE2(
	ke1 *message.KE1,
	record *ClientRecord,
	o *serverOptions, ku *ecc.Scalar,
) (*message.KE2, *ServerOutput) {
	response := s.credentialResponse(ke1.BlindedMessage,
		record.RegistrationRecord, o.MaskingNonce, s.ServerKeyMaterial.PublicKeyBytes, ku)

	identities := (&ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.ServerKeyMaterial.Identity,
	}).SetIdentities(record.ClientPublicKey, s.ServerKeyMaterial.PublicKeyBytes)

	ke2 := &message.KE2{
		CredentialResponse: response,
		ServerKeyShare:     s.conf.Group.Base().Multiply(o.SecretKeyShare),
		ServerNonce:        o.AKENonce,
		ServerMac:          nil,
	}

	clientMac, sessionSecret := ake.Respond(
		s.conf,
		s.ServerKeyMaterial.PrivateKey,
		o.SecretKeyShare,
		identities,
		record.ClientPublicKey,
		ke2,
		ke1,
	)

	return ke2, &ServerOutput{
		ClientMAC:     clientMac,
		SessionSecret: sessionSecret,
	}
}

// chooseOPRFKey chooses the OPRF key to use for the client. If the clientOPRFKey is provided, it will be used directly.
// Otherwise, it will derive the OPRF key from the clientCredentialIdentifier and the global OPRF seed.
func (s *Server) chooseOPRFKey(clientCredentialIdentifier []byte, clientOPRFKey *ecc.Scalar) (*ecc.Scalar, error) {
	if clientOPRFKey != nil {
		if err := IsValidScalar(s.conf.OPRF.Group(), clientOPRFKey); err != nil {
			return nil, ErrServerOptions.Join(internal.ErrClientOPRFKey, err)
		}

		return clientOPRFKey, nil
	}

	if len(clientCredentialIdentifier) == 0 {
		return nil, internal.ErrNoCredentialIdentifier
	}

	return s.deriveOPRFKey(clientCredentialIdentifier)
}

// deriveOPRFKey derives the client OPRF key from the credentialIdentifier and global OPRF seed.
func (s *Server) deriveOPRFKey(clientCredentialIdentifier []byte) (*ecc.Scalar, error) {
	if s.ServerKeyMaterial == nil {
		return nil, ErrServerKeyMaterial.Join(internal.ErrServerKeyMaterialNil)
	}

	if err := s.isOPRFSeedValid(s.ServerKeyMaterial.OPRFGlobalSeed); err != nil {
		return nil, ErrServerKeyMaterial.Join(err)
	}

	seed := s.conf.KDF.Expand(
		s.ServerKeyMaterial.OPRFGlobalSeed,
		encoding.SuffixString(clientCredentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	)

	return s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair)), nil
}

func (s *Server) credentialResponse(
	blindedMessage *ecc.Element,
	record *message.RegistrationRecord,
	maskingNonce, pks []byte,
	ku *ecc.Scalar,
) *message.CredentialResponse {
	z := s.conf.OPRF.Evaluate(ku, blindedMessage)
	maskingNonce, maskedResponse := masking.Mask(
		s.conf,
		maskingNonce,
		record.MaskingKey,
		pks,
		record.Envelope,
	)

	return message.NewCredentialResponse(z, maskingNonce, maskedResponse)
}

type serverOptions struct {
	ClientOPRFKey  *ecc.Scalar
	MaskingNonce   []byte
	SecretKeyShare *ecc.Scalar
	AKENonce       []byte
}

func (s *Server) verifyRecord(record *ClientRecord) error {
	if record == nil {
		return ErrClientRecord.Join(internal.ErrClientRecordNil)
	}

	if record.RegistrationRecord == nil {
		return ErrClientRecord.Join(internal.ErrNilRegistrationRecord)
	}

	if err := IsValidElement(s.conf.Group, record.ClientPublicKey); err != nil {
		return ErrClientRecord.Join(internal.ErrInvalidClientPublicKey, err)
	}

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return ErrClientRecord.Join(internal.ErrEnvelopeInvalid, internal.ErrInvalidEncodingLength)
	}

	if len(record.MaskingKey) != s.conf.KDF.Size() {
		return ErrClientRecord.Join(internal.ErrEnvelopeInvalid, internal.ErrInvalidMaskingKey)
	}

	if isAllZeros(record.MaskingKey) {
		return ErrClientRecord.Join(internal.ErrInvalidMaskingKey, internal.ErrSliceIsAllZeros)
	}

	return nil
}

func (s *Server) validateKeyMaterial(skm *ServerKeyMaterial) error {
	if skm == nil {
		return ErrServerKeyMaterial.Join(internal.ErrServerKeyMaterialNil)
	}

	if err := IsValidScalar(s.conf.Group, skm.PrivateKey); err != nil {
		return ErrServerKeyMaterial.Join(internal.ErrInvalidPrivateKey, err)
	}

	if pk, err := s.Deserialize.DecodePublicKey(skm.PublicKeyBytes); err != nil {
		return ErrServerKeyMaterial.Join(err)
	} else if !pk.Equal(s.conf.Group.Base().Multiply(skm.PrivateKey)) {
		return ErrServerKeyMaterial.Join(internal.ErrInvalidPublicKeyBytes)
	}

	if skm.OPRFGlobalSeed != nil {
		if err := s.isOPRFSeedValid(skm.OPRFGlobalSeed); err != nil {
			return ErrServerKeyMaterial.Join(err)
		}
	}

	return nil
}

func (s *Server) isOPRFSeedValid(seed []byte) error {
	if len(seed) == 0 {
		return internal.ErrOPRFKeyNoSeed
	}

	if len(seed) != s.conf.Hash.Size() {
		return internal.ErrInvalidOPRFSeedLength
	}

	return nil
}

func (s *Server) verifyRegistrationRequest(req *message.RegistrationRequest) error {
	if req == nil {
		return ErrRegistrationRequest.Join(internal.ErrRegistrationRequestNil)
	}

	if err := IsValidElement(s.conf.OPRF.Group(), req.BlindedMessage); err != nil {
		return ErrRegistrationRequest.Join(internal.ErrInvalidBlindedMessage, err)
	}

	return nil
}

func (s *Server) validateKE1(ke1 *message.KE1) error {
	if ke1 == nil {
		return ErrKE1.Join(internal.ErrKE1Nil)
	}

	if err := IsValidElement(s.conf.OPRF.Group(), ke1.BlindedMessage); err != nil {
		return ErrKE1.Join(internal.ErrInvalidBlindedMessage, err)
	}

	if err := IsValidElement(s.conf.OPRF.Group(), ke1.ClientKeyShare); err != nil {
		return ErrKE1.Join(internal.ErrInvalidClientKeyShare, err)
	}

	if len(ke1.ClientNonce) == 0 {
		return ErrKE1.Join(internal.ErrMissingNonce)
	}

	return nil
}
