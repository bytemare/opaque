// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package opaque implements OPAQUE, an asymmetric password-authenticated key exchange protocol that is secure against
// pre-computation attacks. It enables a client to authenticate to a server without ever revealing its password to the
// server. Protocol details can be found on the IETF RFC page (https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque)
// and on the GitHub specification repository (https://github.com/cfrg/draft-irtf-cfrg-opaque).
package opaque

import (
	"crypto"
	"fmt"
	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"
	"github.com/bytemare/opaque/internal/tag"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	internalKSF "github.com/bytemare/opaque/internal/ksf"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/message"
)

// Group identifies the prime-order group with hash-to-curve capability to use in OPRF and AKE.
type Group byte

const (
	// RistrettoSha512 identifies the Ristretto255 group and SHA-512.
	RistrettoSha512 = Group(ecc.Ristretto255Sha512)

	// decaf448Shake256 identifies the Decaf448 group and Shake-256.
	// decaf448Shake256 = 2.

	// P256Sha256 identifies the NIST P-256 group and SHA-256.
	P256Sha256 = Group(ecc.P256Sha256)

	// P384Sha512 identifies the NIST P-384 group and SHA-384.
	P384Sha512 = Group(ecc.P384Sha384)

	// P521Sha512 identifies the NIST P-512 group and SHA-512.
	P521Sha512 = Group(ecc.P521Sha512)
)

// Available returns whether the Group byte is recognized in this implementation. This allows to fail early when
// working with multiple versions not using the same configuration and ecc.
func (g Group) Available() bool {
	return g == RistrettoSha512 ||
		g == P256Sha256 ||
		g == P384Sha512 ||
		g == P521Sha512
}

// OPRF returns the OPRF Identifier used in the Ciphersuite.
func (g Group) OPRF() oprf.Identifier {
	return oprf.IDFromGroup(g.Group())
}

// Group returns the EC Group used in the Ciphersuite.
func (g Group) Group() ecc.Group {
	return ecc.Group(g)
}

const confIDsLength = 6

// Configuration represents an OPAQUE configuration. Note that OprfGroup and AKEGroup are recommended to be the same,
// as well as KDF, MAC, Hash should be the same.
type Configuration struct {
	Context []byte
	KDF     crypto.Hash    `json:"kdf"`
	MAC     crypto.Hash    `json:"mac"`
	Hash    crypto.Hash    `json:"hash"`
	KSF     ksf.Identifier `json:"ksf"`
	OPRF    Group          `json:"oprf"`
	AKE     Group          `json:"group"`
}

// DefaultConfiguration returns a default configuration with strong parameters.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		OPRF:    RistrettoSha512,
		AKE:     RistrettoSha512,
		KSF:     ksf.Argon2id,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		Context: nil,
	}
}

// Client returns a newly instantiated Client from the Configuration.
func (c *Configuration) Client() (*Client, error) {
	return NewClient(c)
}

// Server returns a newly instantiated Server from the Configuration.
func (c *Configuration) Server() (*Server, error) {
	return NewServer(c)
}

// GenerateOPRFSeed returns a OPRF seed valid in the given configuration.
func (c *Configuration) GenerateOPRFSeed() []byte {
	return RandomBytes(c.Hash.Size())
}

// KeyGen returns a key pair in the AKE ecc.
func (c *Configuration) KeyGen() (secretKey *ecc.Scalar, publicKey *ecc.Element) {
	return ake.KeyGen(ecc.Group(c.AKE))
}

// verify returns an error on the first non-compliant parameter, nil otherwise.
func (c *Configuration) verify() error {
	if !c.OPRF.Available() || !c.OPRF.OPRF().Available() {
		return ErrInvalidOPRFid
	}

	if !c.AKE.Available() || !c.AKE.Group().Available() {
		return ErrInvalidAKEid
	}

	if !internal.IsHashFunctionValid(c.KDF) {
		return ErrInvalidKDFid
	}

	if !internal.IsHashFunctionValid(c.MAC) {
		return ErrInvalidMACid
	}

	if !internal.IsHashFunctionValid(c.Hash) {
		return ErrInvalidHASHid
	}

	if c.KSF != 0 && !c.KSF.Available() {
		return ErrInvalidKSFid
	}

	return nil
}

// toInternal builds the internal representation of the configuration parameters.
func (c *Configuration) toInternal() (*internal.Configuration, error) {
	if err := c.verify(); err != nil {
		return nil, err
	}

	g := c.AKE.Group()
	o := c.OPRF.OPRF()
	mac := internal.NewMac(c.MAC)
	ip := &internal.Configuration{
		OPRF:         o,
		Group:        g,
		KSF:          internalKSF.NewKSF(c.KSF),
		KDF:          internal.NewKDF(c.KDF),
		MAC:          mac,
		Hash:         internal.NewHash(c.Hash),
		NonceLen:     internal.NonceLength,
		EnvelopeSize: internal.NonceLength + mac.Size(),
		Context:      c.Context,
	}

	return ip, nil
}

// Deserializer returns a pointer to a Deserializer structure allowing deserialization of messages in the given
// configuration.
func (c *Configuration) Deserializer() (*Deserializer, error) {
	conf, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	return &Deserializer{conf: conf}, nil
}

// Serialize returns the byte encoding of the Configuration structure.
func (c *Configuration) Serialize() []byte {
	ids := []byte{
		byte(c.OPRF),
		byte(c.AKE),
		byte(c.KSF),
		byte(c.KDF),
		byte(c.MAC),
		byte(c.Hash),
	}

	return encoding.Concatenate(ids, encoding.EncodeVector(c.Context))
}

// DeserializeConfiguration decodes the input and returns a Parameter structure.
func DeserializeConfiguration(encoded []byte) (*Configuration, error) {
	// corresponds to the configuration length + 2-byte encoding of empty context
	if len(encoded) < confIDsLength+2 {
		return nil, internal.ErrConfigurationInvalidLength
	}

	ctx, _, err := encoding.DecodeVector(encoded[confIDsLength:])
	if err != nil {
		return nil, fmt.Errorf("decoding the configuration context: %w", err)
	}

	c := &Configuration{
		OPRF:    Group(encoded[0]),
		AKE:     Group(encoded[1]),
		KSF:     ksf.Identifier(encoded[2]),
		KDF:     crypto.Hash(encoded[3]),
		MAC:     crypto.Hash(encoded[4]),
		Hash:    crypto.Hash(encoded[5]),
		Context: ctx,
	}

	if err2 := c.verify(); err2 != nil {
		return nil, err2
	}

	return c, nil
}

// GetFakeRecord creates a fake Client record to be used when no existing client record exists,
// to defend against client enumeration techniques.
func (c *Configuration) GetFakeRecord(credentialIdentifier []byte) (*ClientRecord, error) {
	i, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	scalar := i.Group.NewScalar().Random()
	publicKey := i.Group.Base().Multiply(scalar)

	regRecord := &message.RegistrationRecord{
		ClientPublicKey: publicKey,
		MaskingKey:      RandomBytes(i.KDF.Size()),
		Envelope:        make([]byte, internal.NonceLength+i.MAC.Size()),
	}

	return &ClientRecord{
		CredentialIdentifier: credentialIdentifier,
		ClientIdentity:       nil,
		RegistrationRecord:   regRecord,
	}, nil
}

// ClientRecord is a server-side structure enabling the storage of user relevant information.
type ClientRecord struct {
	*message.RegistrationRecord
	CredentialIdentifier []byte
	ClientIdentity       []byte
}

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	return internal.RandomBytes(length)
}

// IsValidScalar checks if the provided scalar is valid for the given group.
func IsValidScalar(g ecc.Group, s *ecc.Scalar) error {
	if s == nil {
		return ErrScalarNil
	}

	if s.Group() != g {
		return ErrScalarGroupMismatch
	}

	// Check if the scalar is zero.
	if s.IsZero() {
		return ErrScalarZero
	}

	return nil
}

// IsValidElement checks if the provided element is valid for the given group.
func IsValidElement(g ecc.Group, e *ecc.Element) error {
	if e == nil {
		return ErrElementNil
	}

	if e.Group() != g {
		return ErrElementGroupMismatch
	}

	// Check if the element is the identity element (point at infinity).
	if e.IsIdentity() {
		return ErrElementIdentity
	}

	return nil
}

// AKEOptions override the secure default values or internally generated values. It is recommended to use NewAKEOptions
// to instantiate, or the lengths will be set to zero, which is not secure. Only use this if you know what you're
// doing. Reusing seeds and nonces across sessions is a security risk, and breaks forward secrecy.
type AKEOptions struct {
	EphemeralSecretKeyShare *ecc.Scalar
	SecretKeyShareSeed      []byte
	Nonce                   []byte
}

// NewAKEOptions returns a new AKEOptions structure with secure default values. Use this to ensure that secure lengths
// are set by default.
func NewAKEOptions() *AKEOptions {
	return &AKEOptions{
		EphemeralSecretKeyShare: nil,
		SecretKeyShareSeed:      nil,
		Nonce:                   nil,
		// TODO: maybe add KE1 here
		// TODO: "ExportState" to transfer the state?
	}
}

func processAkeOptions2(g ecc.Group, o *AKEOptions) error {
	if o == nil {
		return nil
	}

	if o.EphemeralSecretKeyShare != nil {
		if err := IsValidScalar(g, o.EphemeralSecretKeyShare); err != nil {
			return fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
		}
	}

	return nil
}

func processAkeOptions(g ecc.Group, o *AKEOptions) (*ecc.Scalar, []byte, error) {
	if o == nil {
		o = NewAKEOptions()
	}

	esk, err := determineEphemeralSecretKey(g, o.EphemeralSecretKeyShare, o.SecretKeyShareSeed, internal.SeedLength)
	if err != nil {
		return nil, nil, err
	}

	nonce, err := ake.DetermineNonceOrSeed(o.Nonce, internal.NonceLength, internal.NonceLength)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid AKE key share nonce: %w", err)
	}

	return esk, nonce, nil
}

func determineEphemeralSecretKey(g ecc.Group, esk *ecc.Scalar, seed []byte, seedLength int) (*ecc.Scalar, error) {
	// If an ephemeral secret key share is provided, we check it, and use it.
	if esk != nil {
		if err := IsValidScalar(g, esk); err != nil {
			return nil, fmt.Errorf("%w: %w", errClientOptionsPrefix, err)
		}

		return esk, nil
	}

	// If no ephemeral secret key share is provided, we generate one from the seed.
	s, err := ake.DetermineNonceOrSeed(seed, seedLength, internal.SeedLength)
	if err != nil {
		return nil, fmt.Errorf("invalid AKE key share seed: %w", err)
	}

	esk = oprf.IDFromGroup(g).DeriveKey(s, []byte(tag.DeriveDiffieHellmanKeyPair))

	return esk, nil
}
