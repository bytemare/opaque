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
	"github.com/bytemare/opaque/internal/oprf"
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
		return fmt.Errorf("%w: %w", ErrServerKeyMaterialInvalidEncoding, err)
	}

	sk := g.Group().NewScalar()
	if err := sk.Decode(skBytes); err != nil {
		return fmt.Errorf("%w: %w", ErrServerKeyMaterialInvalidPrivateKeyEncoding, err)
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
		return fmt.Errorf("%w: %w", ErrServerKeyMaterialDecoding, err)
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
// identifiers.
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
	credentialIdentifier []byte, // The credentialIdentifier and global OPRF seed derive the client
	// specific OPRF key. If nil, this yields the same OPRF key for all clients. The same credentialIdentifier should
	// be used for the same client across registration and login, and be different for each client. The globalOPRFSeed
	// can be the same for all clients to prevent client enumeration attacks, but can also be set to nil if the
	// clientOPRFSeed is provided directly.
	overrideClientOPRFKey ...*ecc.Scalar, // Optional. If set, this will be used as the client OPRF key directly instead
	// of deriving it from the credentialIdentifier and globalOPRFSeed.
) (*message.RegistrationResponse, error) {
	if len(serverPublicKeyBytes) != s.conf.Group.ElementLength() {
		return nil, ErrServerInvalidPublicKeyLength
	}

	var clientOPRFKey *ecc.Scalar
	if len(overrideClientOPRFKey) != 0 && overrideClientOPRFKey[0] != nil {
		clientOPRFKey = overrideClientOPRFKey[0]
	}

	ku, err := s.getOPRFKey(credentialIdentifier, clientOPRFKey)
	if err != nil {
		return nil, err
	}

	defer func() {
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
	// Input and parameter validation.
	if err := s.validateKeyMaterial(s.ServerKeyMaterial); err != nil {
		return nil, nil, err
	}

	o := &serverOptions{
		ClientOPRFKey:      nil,
		MaskingNonce:       nil,
		EphemeralSecretKey: nil,
		AKENonce:           nil,
	}

	err := s.parseOptions(o, options)
	if err != nil {
		return nil, nil, fmt.Errorf("getting server options: %w", err)
	}

	var oprfKey *ecc.Scalar

	defer func() {
		internal.ClearScalar(o.EphemeralSecretKey)

		if o.ClientOPRFKey == nil {
			// we clear the oprfKey only if it was derived from the credentialIdentifier and globalOPRFSeed.
			internal.ClearScalar(oprfKey)
		}
	}()

	oprfKey, err = s.getOPRFKey(record.CredentialIdentifier, o.ClientOPRFKey)
	if err != nil {
		return nil, nil, err
	}

	if err = s.verifyRecord(record); err != nil {
		return nil, nil, err
	}

	if err = s.validateKE1(ke1); err != nil {
		return nil, nil, err
	}

	// All input and parameters have been verified for correctness, we can now proceed to generate the KE2 message.
	ke2, out := s.coreGenerateKE2(ke1, record, o, oprfKey)

	return ke2, out, nil
}

// LoginFinish verifies whether the KE3 message holds the client MAC that matches expectedClientMac. If this method
// returns an error, the session secret must not be used. If it returns nil, the session secret can be used.
func (s *Server) LoginFinish(ke3 *message.KE3, expectedClientMac []byte) error {
	if ok := ake.VerifyClientMac(s.conf, ke3, expectedClientMac); !ok {
		return ErrAkeInvalidClientMac
	}

	return nil
}

func (s *Server) coreGenerateKE2(
	ke1 *message.KE1,
	record *ClientRecord,
	so *serverOptions, oprfKey *ecc.Scalar,
) (*message.KE2, *ServerOutput) {
	// Todo: this could be precomputed. Maybe part of the key material.
	pksBytes := s.conf.Group.Base().Multiply(s.ServerKeyMaterial.PrivateKey).Encode()
	response := s.credentialResponse(ke1.BlindedMessage,
		record.RegistrationRecord, so.MaskingNonce, pksBytes, oprfKey)

	identities := (&ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.ServerKeyMaterial.Identity,
	}).SetIdentities(record.ClientPublicKey, pksBytes)

	ke2 := &message.KE2{
		CredentialResponse:   response,
		ServerPublicKeyshare: s.conf.Group.Base().Multiply(so.EphemeralSecretKey),
		ServerNonce:          so.AKENonce,
		ServerMac:            nil,
	}

	clientMac, sessionSecret := ake.Respond(
		s.conf,
		s.ServerKeyMaterial.PrivateKey,
		so.EphemeralSecretKey,
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

func (s *Server) verifyBlindedMessage(blinded *ecc.Element) error {
	return IsValidElement(s.conf.OPRF.Group(), blinded)
}

func (s *Server) verifyRegistrationRequest(req *message.RegistrationRequest) error {
	if req == nil {
		return ErrServerNilRegistrationRequest
	}

	if err := s.verifyBlindedMessage(req.BlindedMessage); err != nil {
		return fmt.Errorf("invalid blinded message in registration request: %w", err)
	}

	return nil
}

func (s *Server) getOPRFKey(credentialIdentifier []byte, clientOPRFKey *ecc.Scalar) (*ecc.Scalar, error) {
	if clientOPRFKey != nil {
		if len(s.ServerKeyMaterial.OPRFGlobalSeed) != 0 || len(credentialIdentifier) != 0 {
			return nil, fmt.Errorf("%w: cannot set overrideClientOPRFKey with a credentialIdentifier and global"+
				"OPRF seed", ErrCredentialIdentifierWithSeed)
		}

		if err := IsValidScalar(s.conf.OPRF.Group(), clientOPRFKey); err != nil {
			return nil, err
		}

		return clientOPRFKey, nil
	}

	if s.ServerKeyMaterial == nil || len(s.ServerKeyMaterial.OPRFGlobalSeed) == 0 {
		return nil, ErrServerKeyMaterialNoOPRFSeed
	}

	return s.deriveOPRFClientKey(credentialIdentifier, s.ServerKeyMaterial.OPRFGlobalSeed)
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

	if len(record.CredentialIdentifier) == 0 {
		return ErrNoCredentialIdentifier
	}

	if record.ClientPublicKey == nil {
		return ErrClientRecordNilPubKey
	}

	if record.ClientPublicKey.Group() != s.conf.Group {
		return ErrClientRecordPublicKeyGroupMismatch
	}

	if record.ClientPublicKey.IsIdentity() {
		return fmt.Errorf("%w: client public key is identity", ErrClientRecordPublicKeyGroupMismatch)
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
		return fmt.Errorf("%w: %w: %w", ErrServerKeyMaterial, ErrServerKeyMaterialInvalidPrivateKey, err)
	}

	if skm.OPRFGlobalSeed != nil {
		if err := s.isOPRFSeedValid(skm.OPRFGlobalSeed); err != nil {
			return err
		}
	}

	return nil
}

func (s *Server) validateKE1(ke1 *message.KE1) error {
	if ke1 == nil || ke1.CredentialRequest == nil || ke1.BlindedMessage == nil {
		return ErrServerNilKE1
	}

	if err := s.verifyBlindedMessage(ke1.BlindedMessage); err != nil {
		return fmt.Errorf("invalid blinded message in KE1: %w", err)
	}

	// todo: cepk should have been checked for identity. What happens if it is identity?

	return nil
}

func (s *Server) deriveOPRFClientKey(credentialIdentifier, globalOPRFSeed []byte) (*ecc.Scalar, error) {
	if len(credentialIdentifier) == 0 {
		return nil, ErrNoCredentialIdentifier
	}

	if len(globalOPRFSeed) == 0 {
		return nil, ErrOPRFKeyNoSeed
	}

	if err := s.isOPRFSeedValid(globalOPRFSeed); err != nil {
		return nil, err
	}

	seed := s.conf.KDF.Expand(
		globalOPRFSeed,
		encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	)

	return s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair)), nil
}

func (s *Server) isOPRFSeedValid(seed []byte) error {
	if len(seed) == 0 {
		return ErrServerKeyMaterialNoOPRFSeed
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
			return ErrServerOptionsClientOPRFKey
		}

		o.ClientOPRFKey = s.conf.OPRF.Group().NewScalar().Set(options[0].ClientOPRFKey)
	}

	// MaskingNonce.
	if len(options[0].MaskingNonce) != 0 {
		if len(options[0].MaskingNonce) != s.conf.NonceLen {
			return ErrServerOptionsMaskingNonceLength
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
		return err
	}

	return nil
}

// getEphemeralSecretKeyShare assumes either EphemeralSecretKeyShare is set or SecretKeyShareSeed is != 0.
func (o *AKEOptions) getEphemeralSecretKeyShare(g ecc.Group) (*ecc.Scalar, error) {
	if o.EphemeralSecretKeyShare != nil {
		if err := IsValidScalar(g, o.EphemeralSecretKeyShare); err != nil {
			return nil, fmt.Errorf("invalid EphemeralSecretKeyShare: %w", err)
		}

		return g.NewScalar().Set(o.EphemeralSecretKeyShare), nil
	}

	return makeESK(g, o.SecretKeyShareSeed), nil
}

func makeESK(g ecc.Group, seed []byte) *ecc.Scalar {
	if len(seed) == 0 {
		seed = internal.RandomBytes(internal.SeedLength)
	}

	return oprf.IDFromGroup(g).DeriveKey(seed, []byte(tag.DeriveDiffieHellmanKeyPair))
}

func makeEskAndNonce(g ecc.Group) (*ecc.Scalar, []byte) {
	return makeESK(g, nil), internal.RandomBytes(internal.NonceLength)
}
