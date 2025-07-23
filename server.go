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
	"fmt"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/masking"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	// ErrNoCredentialIdentifier indicates no credential identifier has been provided.
	ErrNoCredentialIdentifier = errors.New("no credential identifier provided")

	// ErrCredentialIdentifierWithSeed indicates that the credential identifier should not be provided if the client
	//  OPRF seed is set. This is to avoid confusion in the usage of the secret OPRF seed.
	ErrCredentialIdentifierWithSeed = errors.New("the credential identifier should not be provided with a client" +
		"OPRF seed, to avoid usage confusion")

	// ErrAkeInvalidClientMac indicates that the MAC contained in the KE3 message is not valid in the given session.
	ErrAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

	// ErrInvalidState indicates that the given state is not valid due to a wrong length.
	ErrInvalidState = errors.New("invalid state length")

	errKeyMaterialPrefix = errors.New("invalid server key material")

	// ErrServerKeyMaterialNilPKS indicates that the server's public key is nil.
	ErrServerKeyMaterialNilPKS = fmt.Errorf("%w: server public key is nil", errKeyMaterialPrefix)

	// ErrServerKeyMaterialPKSInvalidLength indicates the input public key is not of right length.
	ErrServerKeyMaterialPKSInvalidLength = fmt.Errorf("%w: server public key length is invalid", errKeyMaterialPrefix)

	// ErrServerKeyMaterialPKSBase indicates that the server's public key is the group base element.
	ErrServerKeyMaterialPKSBase = fmt.Errorf(
		"%w: server public key cannot be the group base element",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialNoOPRFSeed indicates no OPRF seed has been provided.
	ErrServerKeyMaterialNoOPRFSeed = fmt.Errorf("%w: no OPRF seed provided", errKeyMaterialPrefix)

	// ErrServerKeyMaterialNil indicates that the server's key material has not been set.
	ErrServerKeyMaterialNil = fmt.Errorf(
		"%w: key material not set - call SetKeyMaterial() to set values",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialInvalid indicates that the server's key material is not valid.
	ErrServerKeyMaterialInvalid = fmt.Errorf(
		"%w: use SetKeyMaterial() to set and validate values",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialInvalidOPRFSeedLength indicates that the OPRF seed is not of right length.
	ErrServerKeyMaterialInvalidOPRFSeedLength = fmt.Errorf(
		"%w: invalid OPRF seed length (must be of hash output length)",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialZeroSKS indicates that the server's private key is a zero scalar.
	ErrServerKeyMaterialZeroSKS = fmt.Errorf("%w: server private key is zero", errKeyMaterialPrefix)

	// ErrServerKeyMaterialNilSKS indicates that the server's private key is a nil.
	ErrServerKeyMaterialNilSKS = fmt.Errorf("%w: server private key is nil", errKeyMaterialPrefix)

	// ErrServerKeyMaterialSKSInvalidGroup indicates that the server's secret key does not match the configuration's group.
	ErrServerKeyMaterialSKSInvalidGroup = fmt.Errorf(
		"%w: server secret key does not match the configuration's group",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialKeysDontMatch indicates that the secret and public keys do not match.
	ErrServerKeyMaterialKeysDontMatch = fmt.Errorf("%w: secret and public keys do not match", errKeyMaterialPrefix)

	errRecordPrefix = errors.New("invalid client record")

	// ErrClientRecordNil indicates that the client record is nil.
	ErrClientRecordNil = fmt.Errorf("%w: client record is nil", errRecordPrefix)

	// ErrClientRecordNilRegistrationRecord indicates that the registration record contained in the client record is nil.
	ErrClientRecordNilRegistrationRecord = fmt.Errorf("%w: registration record is nil", errRecordPrefix)

	// ErrClientRecordNilPubKey indicates that the client's public key is nil.
	ErrClientRecordNilPubKey = fmt.Errorf("%w: client public key is nil", errRecordPrefix)

	// ErrClientRecordPublicKeyGroupMismatch indicates that the client's public key group does not match the
	// configuration's group.
	ErrClientRecordPublicKeyGroupMismatch = fmt.Errorf(
		"%w: client public key group does not match the configuration's group",
		errRecordPrefix,
	)

	// ErrClientRecordInvalidEnvelopeLength indicates the envelope contained in the record is of invalid length.
	ErrClientRecordInvalidEnvelopeLength = fmt.Errorf("%w: invalid envelope length", errRecordPrefix)

	// ErrClientRecordInvalidMaskingKeyLength indicates that the length of the masking key contained in the record
	// is not valid.
	ErrClientRecordInvalidMaskingKeyLength = fmt.Errorf("%w: invalid masking key length", errRecordPrefix)
)

// Server represents an OPAQUE Server, exposing its functions and holding its state.
type Server struct {
	Deserialize *Deserializer
	conf        *internal.Configuration
	Ake         *ake.Server
	keyMaterial *keyMaterial
}

func (s *Server) GetEphemeralSecretKey() *ecc.Scalar {
	if s.keyMaterial == nil || s.keyMaterial.serverSecretKey == nil {
		return nil
	}

	return s.keyMaterial.serverSecretKey.Copy()
}

type keyMaterial struct {
	serverSecretKey      *ecc.Scalar
	serverIdentity       []byte
	serverPublicKeyBytes []byte
	oprfGlobalSeed       []byte
	valid                bool
}

func (k *keyMaterial) flush() {
	if k.serverSecretKey != nil {
		k.serverSecretKey.Zero()
		k.serverSecretKey = nil
	}
	k.serverIdentity = nil
	k.serverPublicKeyBytes = nil
	k.oprfGlobalSeed = nil
	k.valid = false
}

func (s *keyMaterial) isValidPublicKey(g ecc.Group) (*ecc.Element, error) {
	if s.serverPublicKeyBytes == nil {
		s.valid = false

		return nil, ErrServerKeyMaterialNilPKS
	}

	if len(s.serverPublicKeyBytes) != g.ElementLength() {
		s.valid = false
		return nil, ErrServerKeyMaterialPKSInvalidLength
	}

	pks := g.NewElement()
	if err := pks.Decode(s.serverPublicKeyBytes); err != nil {
		s.valid = false
		return nil, fmt.Errorf("%w: %w: %w", errKeyMaterialPrefix, errInvalidServerPK, err)
	}

	if pks.Equal(g.Base()) {
		s.valid = false
		return nil, ErrServerKeyMaterialPKSBase
	}

	if s.serverSecretKey != nil && !g.Base().Multiply(s.serverSecretKey).Equal(pks) {
		s.valid = false
		return nil, ErrServerKeyMaterialKeysDontMatch
	}

	return pks, nil
}

// isValidSecretKey checks whether the server's secret key is valid. It checks that the secret key is not nil, not zero,
// that it matches the provided group and the public key, if provided.
func (s *keyMaterial) isValidSecretKey(g ecc.Group, pks *ecc.Element) error {
	if s.serverSecretKey == nil {
		s.valid = false
		return ErrServerKeyMaterialNilSKS
	}

	if s.serverSecretKey.IsZero() {
		s.valid = false
		return ErrServerKeyMaterialZeroSKS
	}

	if s.serverSecretKey.Group() != g {
		s.valid = false
		return ErrServerKeyMaterialSKSInvalidGroup
	}

	if pks != nil && !g.Base().Multiply(s.serverSecretKey).Equal(pks) {
		s.valid = false
		return ErrServerKeyMaterialKeysDontMatch
	}

	return nil
}

func (s *keyMaterial) isValidGlobalOPRFSeed(c *internal.Configuration) error {
	if err := isOPRFSeedValid(c, s.oprfGlobalSeed); err != nil {
		s.valid = false
		return err
	}

	return nil
}

// isValid verifies whether the server's key material is valid. The server's AKE secret key and the global OPRF seed are
// optional, but if provided, they must be valid.
func (s *keyMaterial) isValid(c *internal.Configuration) error {
	s.valid = false

	if len(s.serverPublicKeyBytes) != c.Group.ElementLength() {
		return ErrServerKeyMaterialPKSInvalidLength
	}

	pks, err := s.isValidPublicKey(c.Group)
	if err != nil {
		return err
	}

	if s.serverSecretKey != nil {
		if err = s.isValidSecretKey(c.Group, pks); err != nil {
			return err
		}
	}

	if s.oprfGlobalSeed != nil {
		if err = s.isValidGlobalOPRFSeed(c); err != nil {
			return err
		}
	}

	if s.serverIdentity == nil {
		s.serverIdentity = s.serverPublicKeyBytes
	}

	s.valid = true

	return nil
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
		keyMaterial: nil,
	}, nil
}

// GetConf return the internal configuration.
func (s *Server) GetConf() *internal.Configuration {
	return s.conf
}

func (s *Server) oprfResponse(element *ecc.Element, seed []byte) *ecc.Element {
	ku := s.conf.OPRF.DeriveKey(seed, []byte(tag.DeriveKeyPair))
	return s.conf.OPRF.Evaluate(ku, element)
}

func isOPRFSeedValid(c *internal.Configuration, seed []byte) error {
	if len(seed) == 0 {
		return ErrServerKeyMaterialNoOPRFSeed
	}

	if len(seed) != 0 && len(seed) != c.Hash.Size() {
		return ErrServerKeyMaterialInvalidOPRFSeedLength
	}

	return nil
}

func (s *Server) deriveOPRFSeed(oprfGlobalSeed, credentialIdentifier []byte) ([]byte, error) {
	if credentialIdentifier == nil {
		return nil, ErrNoCredentialIdentifier
	}

	if err := isOPRFSeedValid(s.conf, oprfGlobalSeed); err != nil {
		return nil, err
	}

	return s.conf.KDF.Expand(
		oprfGlobalSeed,
		encoding.SuffixString(credentialIdentifier, tag.ExpandOPRF),
		internal.SeedLength,
	), nil
}

func (s *Server) chooseOPRFSeed(clientOPRFSeed, credentialIdentifier []byte) ([]byte, error) {
	// If the clientOPRFSeed is provided, we use it directly to derive the OPRF key for the client.
	if clientOPRFSeed != nil {
		if len(credentialIdentifier) != 0 {
			return nil, ErrCredentialIdentifierWithSeed
		}

		if err := isOPRFSeedValid(s.conf, clientOPRFSeed); err != nil {
			return nil, err
		}

		return clientOPRFSeed, nil
	}

	// Otherwise, we derive the OPRF seed from the global OPRF seed and the credential identifier.
	return s.deriveOPRFSeed(s.keyMaterial.oprfGlobalSeed, credentialIdentifier)
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
	credentialIdentifier []byte, // optional, can be nil. Used with the global OPRF seed if clientOPRFSeed is nil.
	clientOPRFSeed []byte, // optional, can be nil. Overrides the global OPRF seed for this request.
) (*message.RegistrationResponse, error) {
	if s.keyMaterial == nil {
		return nil, ErrServerKeyMaterialNil
	}

	if !s.keyMaterial.valid {
		return nil, ErrServerKeyMaterialInvalid
	}

	oprfSeed, err := s.chooseOPRFSeed(clientOPRFSeed, credentialIdentifier)
	if err != nil {
		return nil, err
	}

	z := s.oprfResponse(req.BlindedMessage, oprfSeed)

	return &message.RegistrationResponse{
		EvaluatedMessage: z,
		ServerPublicKey:  s.keyMaterial.serverPublicKeyBytes,
	}, nil
}

func (s *Server) credentialResponse(
	req *message.CredentialRequest,
	record *message.RegistrationRecord,
	maskingNonce, oprfSeed []byte,
) *message.CredentialResponse {
	z := s.oprfResponse(req.BlindedMessage, oprfSeed)

	maskingNonce, maskedResponse := masking.Mask(
		s.conf,
		maskingNonce,
		record.MaskingKey,
		s.keyMaterial.serverPublicKeyBytes,
		record.Envelope,
	)

	return message.NewCredentialResponse(z, maskingNonce, maskedResponse)
}

// ServerOptions enable setting optional values for the session, which default to secure random values if not
// set.
type ServerOptions struct {
	ClientOPRFSeed []byte
	KeyShareSeed   []byte
	AKENonce       []byte
	MaskingNonce   []byte
	AKE            AKEOptions
	AKENonceLength int
}

func getServerOptions(options []ServerOptions) (*ake.Options, []byte, []byte, error) {
	var maskingNonce, oprfSeed []byte

	op := ake.NewOptions()

	if len(options) != 0 {
		op.EphemeralKeyShareSeed = options[0].KeyShareSeed
		maskingNonce = options[0].MaskingNonce
		oprfSeed = options[0].ClientOPRFSeed

		if err := op.Set(options[0].KeyShareSeed, options[0].AKE.KeyShareSeedLength, options[0].AKENonce, options[0].AKENonceLength); err != nil {
			return nil, nil, nil, fmt.Errorf("setting AKE options: %w", err)
		}
	} else {
		op.Nonce = internal.RandomBytes(internal.NonceLength)
		op.EphemeralKeyShareSeed = internal.RandomBytes(internal.NonceLength)
	}

	return op, maskingNonce, oprfSeed, nil
}

// SetKeyMaterial set the server's identity and mandatory key material to be used during GenerateKE2().
// All these values must be the same as used during client registration and remain the same across protocol execution
// for a given registered client.
//
// - serverIdentity can be nil, in which case it will be set to serverPublicKeyBytes.
// - serverSecretKey is the server's secret AKE key. Can be nil if used in the registration flow.
// - serverPublicKeyBytes is the server's public AKE key to the serverSecretKey, can be nil if used in the login flow,
// as long as serverIdentity is set.
// - oprfGlobalSeed is the long-term OPRF input seed used for all clients.
func (s *Server) SetKeyMaterial(serverIdentity, serverSecretKey, serverPublicKey, oprfGlobalSeed []byte) error {
	var sks *ecc.Scalar
	if len(serverSecretKey) != 0 {
		sks = s.conf.Group.NewScalar()
		if err := sks.Decode(serverSecretKey); err != nil {
			return fmt.Errorf("%w: %w", errKeyMaterialPrefix, err)
		}
	}

	km := &keyMaterial{
		valid:                false,
		serverIdentity:       serverIdentity,
		serverSecretKey:      sks,
		serverPublicKeyBytes: serverPublicKey,
		oprfGlobalSeed:       oprfGlobalSeed,
	}

	if err := km.isValid(s.conf); err != nil {
		return err
	}

	s.keyMaterial = km

	return nil
}

func (s *Server) checkRecord(record *ClientRecord) error {
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

	if len(record.Envelope) != s.conf.EnvelopeSize {
		return ErrClientRecordInvalidEnvelopeLength
	}

	if len(record.MaskingKey) != s.conf.KDF.Size() {
		return ErrClientRecordInvalidMaskingKeyLength
	}

	return nil
}

func (s *Server) validateKeyMaterialForKe2() error {
	if s.keyMaterial == nil {
		return ErrServerKeyMaterialNil
	}

	if !s.keyMaterial.valid {
		return ErrServerKeyMaterialInvalid
	}

	var pks *ecc.Element

	if s.keyMaterial.serverPublicKeyBytes != nil {
		var err error

		pks, err = s.keyMaterial.isValidPublicKey(s.conf.Group)
		if err != nil {
			return err
		}
	}

	if err := s.keyMaterial.isValidSecretKey(s.conf.Group, pks); err != nil {
		return err
	}

	return nil
}

// GenerateKE2 responds to a KE1 message with a KE2 message a client record.
func (s *Server) GenerateKE2(
	ke1 *message.KE1,
	record *ClientRecord,
	options ...ServerOptions,
) (*message.KE2, error) {
	if err := s.checkRecord(record); err != nil {
		return nil, err
	}

	if err := s.validateKeyMaterialForKe2(); err != nil {
		return nil, err
	}

	// We've checked that the server's public key and the client's envelope are of correct length,
	// thus ensuring that the subsequent xor-ing input is the same length as the encryption pad.

	op, maskingNonce, clientOPRFSeed, err := getServerOptions(options)
	if err != nil {
		return nil, fmt.Errorf("getting server options: %w", err)
	}

	oprfSeed, err := s.chooseOPRFSeed(clientOPRFSeed, record.CredentialIdentifier)
	if err != nil {
		return nil, err
	}

	response := s.credentialResponse(ke1.CredentialRequest,
		record.RegistrationRecord, maskingNonce, oprfSeed)

	identities := (&ake.Identities{
		ClientIdentity: record.ClientIdentity,
		ServerIdentity: s.keyMaterial.serverIdentity,
	}).SetIdentities(record.ClientPublicKey, s.keyMaterial.serverPublicKeyBytes)

	esk, epk := ake.MakeKeyShare(s.conf.Group, op.EphemeralKeyShareSeed, op.EphemeralSecretKeyShare)

	serverKM := ake.MakeKeyMaterial2(identities.ServerIdentity,
		op.Nonce,
		esk,
		s.keyMaterial.serverSecretKey,
		epk)
	clientKM := ake.MakePeerKeyMaterial(identities.ClientIdentity,
		ke1.ClientPublicKeyshare,
		record.ClientPublicKey)

	ke2 := s.Ake.Response(s.conf, ke1, response, serverKM, clientKM)

	return ke2, nil
}

// LoginFinish returns an error if the KE3 received from the client holds an invalid mac, and nil if correct.
func (s *Server) LoginFinish(ke3 *message.KE3) error {
	if ok, _ := s.Ake.Finalize(s.conf, ke3); !ok {
		return ErrAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the session key if the previous call to GenerateKE2() was successful.
func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}

// ExpectedMAC returns the expected client MAC if the previous call to GenerateKE2() was successful.
func (s *Server) ExpectedMAC() []byte {
	return s.Ake.ExpectedMAC()
}

// SetAKEState sets the internal state of the AKE server from the given bytes.
func (s *Server) SetAKEState(state []byte) error {
	if len(state) != s.conf.MAC.Size()+s.conf.KDF.Size() {
		return ErrInvalidState
	}

	if err := s.Ake.SetState(state[:s.conf.MAC.Size()], state[s.conf.MAC.Size():]); err != nil {
		return fmt.Errorf("setting AKE state: %w", err)
	}

	return nil
}

// SerializeState returns the internal state of the AKE server serialized to bytes.
func (s *Server) SerializeState() []byte {
	return s.Ake.SerializeState()
}

// Flush sets all the server's session related internal AKE values to nil.
func (s *Server) Flush() {
	s.Ake.Flush()
	s.keyMaterial.flush()
	// TODO: reset mac, hash, kdf, etc. to avoid leaking the state
}
