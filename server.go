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
	"fmt"

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

// ServerKeyMaterial holds the server's core identity and key material for the OPRF and AKE sub-protocols. Note that,
// depending on the setup, these values are not client specific and can be reused across clients.
type ServerKeyMaterial struct {
	// The server's identity. If empty, will be set to the server's public key.
	Identity []byte

	// The server's long-term secret key. Required only for Login, and unused for Registration.
	PrivateKey *ecc.Scalar

	// The seed to derive the OPRF key for the clients with. Recommended to be set for both Registration and Login,
	// but optional if the clientOPRFKey is set.
	OPRFGlobalSeed []byte
}

// Flush does a best-effort attempt to clear the server key material from memory. It is not guaranteed that the contents
// are correctly wiped from memory.
func (s *ServerKeyMaterial) Flush() {
	internal.ClearScalar(s.PrivateKey)
	s.PrivateKey = nil
	internal.ClearSlice(s.OPRFGlobalSeed)
	s.OPRFGlobalSeed = nil
	internal.ClearSlice(s.Identity)
	s.Identity = nil
}

// Encode encodes the server key material into a byte slice.
func (s *ServerKeyMaterial) Encode() []byte {
	return encoding.Concatenate(
		[]byte{byte(s.PrivateKey.Group())},
		encoding.EncodeVector(s.Identity),
		encoding.EncodeVector(s.PrivateKey.Encode()),
		encoding.EncodeVector(s.OPRFGlobalSeed),
	)
}

// Hex encodes the server key material into a hex string.
func (s *ServerKeyMaterial) Hex() string {
	return hex.EncodeToString(s.Encode())
}

// Decode decodes the server key material to s from a byte slice. If an error is encountered, s is unchanged.
func (s *ServerKeyMaterial) Decode(data []byte) error {
	if len(data) < 7 {
		return ErrServerKeyMaterialInvalidEncodingLength
	}

	g := Group(data[0])
	if !g.Available() {
		return ErrServerKeyMaterialInvalidGroupEncoding
	}

	var id, skBytes, seed []byte
	if err := encoding.DecodeLongVector(data[1:], &id, &skBytes, &seed); err != nil {
		return prefixError(ErrServerKeyMaterialDecoding, err)
	}

	sk := g.Group().NewScalar()
	if err := sk.Decode(skBytes); err != nil {
		return prefixError(ErrServerKeyMaterialInvalidPrivateKeyEncoding, err)
	}

	if sk.IsZero() {
		return ErrServerKeyMaterialPrivateKeyZero
	}

	s.Identity = id
	s.PrivateKey = sk
	s.OPRFGlobalSeed = seed

	return nil
}

// DecodeHex decodes the server key material to s from a hex string. If an error is encountered, s is unchanged.
func (s *ServerKeyMaterial) DecodeHex(data string) error {
	if data == "" {
		return ErrServerKeyMaterialDecodingEmptyHex
	}

	decoded, err := hex.DecodeString(data)
	if err != nil {
		return prefixError(ErrServerKeyMaterialDecoding, err)
	}

	return s.Decode(decoded)
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

// ServerOptions override the secure default values or internally generated values.
// Only use this if you know what you're doing. Reusing seeds and nonces across sessions is a security risk,
// and breaks forward secrecy.
type ServerOptions struct {
	ClientOPRFKey *ecc.Scalar
	AKE           *AKEOptions
	MaskingNonce  []byte
}

// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given
// identifiers. This needs a dedicated key for the client throughout the credential lifecycle. This key can either be:
// - derived from the client specific clientCredentialIdentifier and oprfGlobalSeed, set through SetKeyMaterial
// - provided directly as clientOPRFKey. Note that in that case no previous SetKeyMaterial setting is required.
//
// If both the clientCredentialIdentifier and clientOPRFKey are provided, the clientOPRFKey will be used directly.
//
// Refer to the documentation to understand the implications and discussions on the tradeoffs. TODO: mention it
// TODO: clean up this doc
// - The oprfGlobalSeed (set through SetKeyMaterial) SHOULD be used with the same value for all clients to prevent
// client enumeration attacks, but may be chosen not to be if the functionality is not necessary. Using a nil OPRF seed
// is not secure, because it makes guessing the servers OPRF key trivial given the credential identifiers.
// Using the credentialIdentifier, oprfGlobalSeed is then internally used to derive a unique OPRF key for the client.
// - Alternatively, the oprfGlobalSeed can be set to nil and no credentialIdentifier provided, if the clientOPRFSeed is
// provided directly, avoiding the internal derivation. This is useful should the oprfGlobalSeed be used on another
// instance to protect it.
func (s *Server) RegistrationResponse(
	req *message.RegistrationRequest,
	serverPublicKeyBytes []byte, // The server's public key to be sent to the client.
	clientCredentialIdentifier []byte, // The credentialIdentifier and global OPRF seed derive the client
	// specific OPRF key. If nil, this yields the same OPRF key for all clients. The same credentialIdentifier should
	// be used for the same client across registration and login, and be different for each client. The globalOPRFSeed
	// can be the same for all clients to prevent client enumeration attacks, but can also be set to nil if the
	// clientOPRFSeed is provided directly.
	clientOPRFKey *ecc.Scalar, // If set, this will be used as the client OPRF key directly instead
	// of deriving it from the credentialIdentifier and globalOPRFSeed.
) (*message.RegistrationResponse, error) {
	if len(serverPublicKeyBytes) != s.conf.Group.ElementLength() {
		return nil, ErrServerInvalidPublicKeyLength
	}

	ku, err := s.chooseOPRFKey(clientCredentialIdentifier, clientOPRFKey)
	if err != nil {
		return nil, err
	}

	defer func() {
		// If the OPRF key was derived internally, we attempt to wipe it to avoid leaking the key.
		if clientOPRFKey == nil {
			internal.ClearScalar(ku)
		}
	}()

	if err = s.verifyRegistrationRequest(req); err != nil {
		return nil, err
	}

	return &message.RegistrationResponse{
		EvaluatedMessage: s.conf.OPRF.Evaluate(ku, req.BlindedMessage),
		ServerPublicKey:  serverPublicKeyBytes,
	}, nil
}

// ServerOutput is the result of a successful GenerateKE2 call, containing the client MAC and session secret. The
// SessionSecret must not be used before the client's KE3 message has been verified against the ClientMAC.
type ServerOutput struct {
	ClientMAC     []byte
	SessionSecret []byte
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
		ClientOPRFKey:      nil,
		MaskingNonce:       nil,
		EphemeralSecretKey: nil,
		AKENonce:           nil,
	}
	defer internal.ClearScalar(o.ClientOPRFKey)
	defer internal.ClearScalar(o.EphemeralSecretKey)

	err := s.parseOptions(o, options)
	if err != nil {
		return nil, nil, err
	}

	ku, err := s.chooseOPRFKey(record.CredentialIdentifier, o.ClientOPRFKey)
	if err != nil {
		return nil, nil, err
	}

	defer internal.ClearScalar(ku)

	ke2, output := s.coreGenerateKE2(ke1, record, o, ku)

	return ke2, output, nil
}

// LoginFinish verifies whether the KE3 message holds the client MAC that matches expectedClientMac. If this method
// returns an error, the session secret must not be used. If it returns nil, the session secret can be used.
func (s *Server) LoginFinish(ke3 *message.KE3, expectedClientMac []byte) error {
	if ok := ake.VerifyClientMac(s.conf, ke3, expectedClientMac); !ok {
		return ErrClientAuthentication
	}

	return nil
}

func (s *Server) coreGenerateKE2(
	ke1 *message.KE1,
	record *ClientRecord,
	o *serverOptions, ku *ecc.Scalar,
) (*message.KE2, *ServerOutput) {
	// Todo: this could be precomputed. Maybe part of the key material.
	pksBytes := s.conf.Group.Base().Multiply(s.ServerKeyMaterial.PrivateKey).Encode()
	response := s.credentialResponse(ke1.BlindedMessage,
		record.RegistrationRecord, o.MaskingNonce, pksBytes, ku)

	identities := (&ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.ServerKeyMaterial.Identity,
	}).SetIdentities(record.ClientPublicKey, pksBytes)

	ke2 := &message.KE2{
		CredentialResponse:   response,
		ServerPublicKeyshare: s.conf.Group.Base().Multiply(o.EphemeralSecretKey),
		ServerNonce:          o.AKENonce,
		ServerMac:            nil,
	}

	clientMac, sessionSecret := ake.Respond(
		s.conf,
		s.ServerKeyMaterial.PrivateKey,
		o.EphemeralSecretKey,
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

func (s *Server) verifyRegistrationRequest(req *message.RegistrationRequest) error {
	if req == nil {
		return ErrRegistrationRequestNil
	}

	if err := IsValidElement(s.conf.OPRF.Group(), req.BlindedMessage); err != nil {
		return prefixError(ErrServerRegistrationRequestBlindedMessage, err)
	}

	return nil
}

// chooseOPRFKey chooses the OPRF key to use for the client. If the clientOPRFKey is provided, it will be used directly.
// Otherwise, it will derive the OPRF key from the clientCredentialIdentifier and the global OPRF seed.
func (s *Server) chooseOPRFKey(clientCredentialIdentifier []byte, clientOPRFKey *ecc.Scalar) (*ecc.Scalar, error) {
	if clientOPRFKey != nil {
		if err := IsValidScalar(s.conf.OPRF.Group(), clientOPRFKey); err != nil {
			return nil, prefixError(ErrServerOptionsClientOPRFKey, err)
		}

		return clientOPRFKey, nil
	}

	return s.deriveOPRFKey(clientCredentialIdentifier)
}

// deriveOPRFKey derives the client OPRF key from the credentialIdentifier and global OPRF seed.
func (s *Server) deriveOPRFKey(clientCredentialIdentifier []byte) (*ecc.Scalar, error) {
	if len(clientCredentialIdentifier) == 0 {
		return nil, ErrNoCredentialIdentifier
	}

	if s.ServerKeyMaterial == nil {
		return nil, ErrServerKeyMaterialNil
	}

	if len(s.ServerKeyMaterial.OPRFGlobalSeed) == 0 {
		return nil, ErrServerKeymaterialOPRFKeyNoSeed
	}

	if err := s.isOPRFSeedValid(s.ServerKeyMaterial.OPRFGlobalSeed); err != nil {
		return nil, err
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
	ClientOPRFKey      *ecc.Scalar
	MaskingNonce       []byte
	EphemeralSecretKey *ecc.Scalar
	AKENonce           []byte
}

func (s *Server) verifyRecord(record *ClientRecord) error {
	if record == nil {
		return ErrClientRecordNil
	}

	if record.RegistrationRecord == nil {
		return ErrClientRecordNilRegistrationRecord
	}

	if record.ClientPublicKey == nil {
		return ErrClientRecordNilPubKey
	}

	if record.ClientPublicKey.Group() != s.conf.Group {
		return ErrClientRecordPublicKeyGroupMismatch
	}

	if record.ClientPublicKey.IsIdentity() {
		return ErrClientRecordPublicKeyIdentity
	}

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return ErrClientRecordInvalidEnvelopeLength
	}

	if len(record.MaskingKey) != s.conf.KDF.Size() {
		return ErrClientRecordInvalidMaskingKeyLength
	}

	return nil
}

func (s *Server) validateKeyMaterial(skm *ServerKeyMaterial) error {
	if skm == nil {
		return ErrServerKeyMaterialNil
	}

	if err := IsValidScalar(s.conf.Group, skm.PrivateKey); err != nil {
		return fmt.Errorf("%w: %w: %w", ErrServerKeyMaterial, ErrInvalidPrivateKey, err)
	}

	if skm.OPRFGlobalSeed != nil {
		if err := s.isOPRFSeedValid(skm.OPRFGlobalSeed); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) validateKE1(ke1 *message.KE1) error {
	if ke1 == nil ||
		ke1.CredentialRequest == nil ||
		ke1.BlindedMessage == nil ||
		ke1.ClientPublicKeyshare == nil ||
		len(ke1.ClientNonce) == 0 {
		return ErrServerKE1Incomplete
	}

	if err := IsValidElement(s.conf.OPRF.Group(), ke1.BlindedMessage); err != nil {
		return prefixError(ErrServerKE1BlindedMessage, err)
	}

	if err := IsValidElement(s.conf.Group, ke1.ClientPublicKeyshare); err != nil {
		return prefixError(ErrServerKE1InvalidClientKeyShare, err)
	}

	return nil
}

func (s *Server) isOPRFSeedValid(seed []byte) error {
	if len(seed) == 0 {
		return ErrServerKeymaterialOPRFKeyNoSeed
	}

	if len(seed) != 0 && len(seed) != s.conf.Hash.Size() {
		return ErrServerKeyMaterialInvalidOPRFSeedLength
	}

	return nil
}

func (s *Server) parseOptions(o *serverOptions, options []*ServerOptions) error {
	if len(options) == 0 || options[0] == nil {
		o.MaskingNonce = internal.RandomBytes(s.conf.NonceLen)
		o.EphemeralSecretKey, o.AKENonce = makeEskAndNonce(s.conf.Group)

		return nil
	}

	// ClientOPRFKey
	if options[0].ClientOPRFKey != nil {
		if err := IsValidScalar(s.conf.OPRF.Group(), options[0].ClientOPRFKey); err != nil {
			return prefixError(ErrServerOptionsClientOPRFKey, err)
		}

		o.ClientOPRFKey = s.conf.OPRF.Group().NewScalar().Set(options[0].ClientOPRFKey)
	}

	// MaskingNonce.
	if len(options[0].MaskingNonce) != 0 {
		if len(options[0].MaskingNonce) != s.conf.NonceLen {
			return prefixError(ErrServerOptions, ErrServerOptionsMaskingNonceLength)
		}

		o.MaskingNonce = make([]byte, len(options[0].MaskingNonce))
		copy(o.MaskingNonce, options[0].MaskingNonce)
	} else {
		o.MaskingNonce = internal.RandomBytes(s.conf.NonceLen)
	}

	// AKE options.
	if options[0].AKE == nil {
		o.EphemeralSecretKey, o.AKENonce = makeEskAndNonce(s.conf.Group)

		return nil
	}

	// AKE nonce.
	if len(options[0].AKE.Nonce) == 0 {
		o.AKENonce = internal.RandomBytes(internal.NonceLength)
	} else {
		o.AKENonce = make([]byte, len(options[0].AKE.Nonce))
		copy(o.AKENonce, options[0].AKE.Nonce)
	}

	// Ephemeral secret key share.
	var err error

	o.EphemeralSecretKey, err = options[0].AKE.getEphemeralSecretKeyShare(s.conf.Group)
	if err != nil {
		return prefixError(ErrServerOptions, err)
	}

	return nil
}
