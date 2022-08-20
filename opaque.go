// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
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
	"errors"
	"fmt"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/message"

	"github.com/bytemare/crypto/group"
	"github.com/bytemare/crypto/hash"
	"github.com/bytemare/crypto/ksf"
)

// Group identifies the prime-order group with hash-to-curve capability to use in OPRF and AKE.
type Group byte

const (
	// RistrettoSha512 identifies the Ristretto255 group and SHA-512.
	RistrettoSha512 = Group(oprf.RistrettoSha512)

	// decaf448Shake256 identifies the Decaf448 group and Shake-256.
	// decaf448Shake256 = 2.

	// P256Sha256 identifies the NIST P-256 group and SHA-256.
	P256Sha256 = Group(oprf.P256Sha256)

	// P384Sha512 identifies the NIST P-384 group and SHA-384.
	P384Sha512 = Group(oprf.P384Sha384)

	// P521Sha512 identifies the NIST P-512 group and SHA-512.
	P521Sha512 = Group(oprf.P521Sha512)

	// Curve25519Sha512 identifies a group over Curve25519 with SHA2-512 hash-to-group hashing.
	// Curve25519Sha512 = Group(group.Curve25519Sha512).
)

// Available returns whether the Group byte is recognized in this implementation. This allows to fail early when
// working with multiple versions not using the same configuration and Group.
func (g Group) Available() bool {
	return g == RistrettoSha512 ||
		g == P256Sha256 ||
		g == P384Sha512 ||
		g == P521Sha512
}

const confLength = 6

var (
	errInvalidOPRFid = errors.New("invalid OPRF group id")
	errInvalidKDFid  = errors.New("invalid KDF id")
	errInvalidMACid  = errors.New("invalid MAC id")
	errInvalidHASHid = errors.New("invalid Hash id")
	errInvalidKSFid  = errors.New("invalid KSF id")
	errInvalidAKEid  = errors.New("invalid AKE group id")
)

// Configuration represents an OPAQUE configuration. Note that OprfGroup and AKEGroup are recommended to be the same,
// as well as KDF, MAC, Hash should be the same.
type Configuration struct {
	// OPRF identifies the ciphersuite to use for the OPRF.
	OPRF Group `json:"oprf"`

	// KDF identifies the hash function to be used for key derivation (e.g. HKDF).
	KDF crypto.Hash `json:"kdf"`

	// MAC identifies the hash function to be used for message authentication (e.g. HMAC).
	MAC crypto.Hash `json:"mac"`

	// Hash identifies the hash function to be used for hashing, as defined in github.com/bytemare/crypto/hash.
	Hash crypto.Hash `json:"hash"`

	// KSF identifies the key stretching function for expensive key derivation on the client,
	// defined in github.com/bytemare/crypto/ksf.
	KSF ksf.Identifier `json:"ksf"`

	// AKE identifies the group to use for the AKE.
	AKE Group `json:"group"`

	// Context is optional shared information to include in the AKE transcript.
	Context []byte
}

// DefaultConfiguration returns a default configuration with strong parameters.
func DefaultConfiguration() *Configuration {
	return &Configuration{
		OPRF:    RistrettoSha512,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		KSF:     ksf.Scrypt,
		AKE:     RistrettoSha512,
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

// KeyGen returns a key pair in the AKE group.
func (c *Configuration) KeyGen() (secretKey, publicKey []byte) {
	return ake.KeyGen(group.Group(c.AKE))
}

// verify returns an error on the first non-compliant parameter, nil otherwise.
func (c *Configuration) verify() error {
	if !c.OPRF.Available() || !oprf.Ciphersuite(c.OPRF).Available() {
		return errInvalidOPRFid
	}

	if !hash.Hashing(c.KDF).Available() {
		return errInvalidKDFid
	}

	if !hash.Hashing(c.MAC).Available() {
		return errInvalidMACid
	}

	if !hash.Hashing(c.Hash).Available() {
		return errInvalidHASHid
	}

	if c.KSF != 0 && !c.KSF.Available() {
		return errInvalidKSFid
	}

	if !c.AKE.Available() || !group.Group(c.AKE).Available() {
		return errInvalidAKEid
	}

	return nil
}

// toInternal builds the internal representation of the configuration parameters.
func (c *Configuration) toInternal() (*internal.Configuration, error) {
	if err := c.verify(); err != nil {
		return nil, err
	}

	g := group.Group(c.AKE)
	ip := &internal.Configuration{
		OPRF:            oprf.Ciphersuite(c.OPRF),
		OPRFPointLength: encoding.PointLength[group.Group(c.OPRF)],
		KDF:             internal.NewKDF(c.KDF),
		MAC:             internal.NewMac(c.MAC),
		Hash:            internal.NewHash(c.Hash),
		KSF:             internal.NewKSF(c.KSF),
		NonceLen:        internal.NonceLength,
		Group:           g,
		AkePointLength:  encoding.PointLength[g],
		Context:         c.Context,
	}
	ip.EnvelopeSize = ip.NonceLen + ip.MAC.Size()

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
	b := []byte{
		byte(c.OPRF),
		byte(c.KDF),
		byte(c.MAC),
		byte(c.Hash),
		byte(c.KSF),
		byte(c.AKE),
	}

	return encoding.Concat(b, encoding.EncodeVector(c.Context))
}

// GetFakeRecord creates a fake Client record to be used when no existing client record exists,
// to defend against client enumeration techniques.
func (c *Configuration) GetFakeRecord(credentialIdentifier []byte) (*ClientRecord, error) {
	i, err := c.toInternal()
	if err != nil {
		return nil, err
	}

	scalar := i.Group.NewScalar().Random()
	publicKey := i.Group.Base().Mult(scalar)

	regRecord := &message.RegistrationRecord{
		G:          i.Group,
		PublicKey:  publicKey,
		MaskingKey: RandomBytes(i.KDF.Size()),
		Envelope:   make([]byte, internal.NonceLength+i.MAC.Size()),
	}

	return &ClientRecord{
		CredentialIdentifier: credentialIdentifier,
		ClientIdentity:       nil,
		RegistrationRecord:   regRecord,
		TestMaskNonce:        nil,
	}, nil
}

// DeserializeConfiguration decodes the input and returns a Parameter structure.
func DeserializeConfiguration(encoded []byte) (*Configuration, error) {
	if len(encoded) < confLength+2 { // corresponds to the configuration length + 2-byte encoding of empty context
		return nil, internal.ErrConfigurationInvalidLength
	}

	ctx, _, err := encoding.DecodeVector(encoded[confLength:])
	if err != nil {
		return nil, fmt.Errorf("decoding the configuration context: %w", err)
	}

	c := &Configuration{
		OPRF:    Group(encoded[0]),
		KDF:     crypto.Hash(encoded[1]),
		MAC:     crypto.Hash(encoded[2]),
		Hash:    crypto.Hash(encoded[3]),
		KSF:     ksf.Identifier(encoded[4]),
		AKE:     Group(encoded[5]),
		Context: ctx,
	}

	if err := c.verify(); err != nil {
		return nil, err
	}

	return c, nil
}

// ClientRecord is a server-side structure enabling the storage of user relevant information.
type ClientRecord struct {
	CredentialIdentifier []byte
	ClientIdentity       []byte
	*message.RegistrationRecord

	// testing
	TestMaskNonce []byte
}

// RandomBytes returns random bytes of length len (wrapper for crypto/rand).
func RandomBytes(length int) []byte {
	return internal.RandomBytes(length)
}
