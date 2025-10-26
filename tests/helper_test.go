// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"crypto"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"

	internalKSF "github.com/bytemare/opaque/internal/ksf"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	for _, c := range configurationTable {
		var err error
		c.internal, err = toInternal(c.conf)
		if err != nil {
			panic(err)
		}
	}
}

var (
	password             = []byte("test-password")
	credentialIdentifier = []byte("test-credential-identifier")
	clientIdentity       = []byte("test-client-identity")
	serverIdentity       = []byte("test-server-identity")
)

type configuration struct {
	curve    elliptic.Curve
	conf     *opaque.Configuration
	internal *internal.Configuration
	name     string
}

func verify(c *opaque.Configuration) error {
	if !c.OPRF.Available() || !c.OPRF.OPRF().Available() {
		return internal.ErrInvalidOPRFid
	}

	if !c.AKE.Available() || !c.AKE.Group().Available() {
		return internal.ErrInvalidAKEid
	}

	if !internal.IsHashFunctionValid(c.KDF) {
		return internal.ErrInvalidKDFid
	}

	if !internal.IsHashFunctionValid(c.MAC) {
		return internal.ErrInvalidMACid
	}

	if !internal.IsHashFunctionValid(c.Hash) {
		return internal.ErrInvalidHASHid
	}

	if c.KSF != 0 && !c.KSF.Available() {
		return internal.ErrInvalidKSFid
	}

	return nil
}

func toInternal(c *opaque.Configuration) (*internal.Configuration, error) {
	if err := verify(c); err != nil {
		return nil, err
	}

	g := c.AKE.Group()
	o := c.OPRF.OPRF()
	mac := internal.NewMac(c.MAC)
	return &internal.Configuration{
		OPRF:         o,
		Group:        g,
		KSF:          internalKSF.NewKSF(c.KSF),
		KDF:          internal.NewKDF(c.KDF),
		MAC:          mac,
		Hash:         internal.NewHash(c.Hash),
		NonceLen:     internal.NonceLength,
		EnvelopeSize: internal.NonceLength + mac.Size(),
		Context:      c.Context,
	}, nil
}

// todo Add test that catches if a suite has been added without being added to the configuration table.
var configurationTable = []*configuration{
	{
		name:  "Ristretto255",
		conf:  opaque.DefaultConfiguration(),
		curve: nil,
	},
	{
		name: "P256Sha256",
		conf: &opaque.Configuration{
			OPRF: opaque.P256Sha256,
			KDF:  crypto.SHA256,
			MAC:  crypto.SHA256,
			Hash: crypto.SHA256,
			KSF:  ksf.Argon2id,
			AKE:  opaque.P256Sha256,
		},
		curve: elliptic.P256(),
	},
	{
		name: "P384Sha512",
		conf: &opaque.Configuration{
			OPRF: opaque.P384Sha512,
			KDF:  crypto.SHA512,
			MAC:  crypto.SHA512,
			Hash: crypto.SHA512,
			KSF:  ksf.Argon2id,
			AKE:  opaque.P384Sha512,
		},
		curve: elliptic.P384(),
	},
	{
		name: "P521Sha512",
		conf: &opaque.Configuration{
			OPRF: opaque.P521Sha512,
			KDF:  crypto.SHA512,
			MAC:  crypto.SHA512,
			Hash: crypto.SHA512,
			KSF:  ksf.Argon2id,
			AKE:  opaque.P521Sha512,
		},
		curve: elliptic.P521(),
	},
}

type testError struct {
	name   string
	f      func() error
	errors []error
}

func testForErrors(t *testing.T, te *testError) {
	t.Helper()
	t.Run(te.name, func(t2 *testing.T) {
		expectErrors(t, te.f, te.errors...)
	})
}

func expectErrors(t *testing.T, f func() error, expected ...error) {
	t.Helper()
	if err := f(); err == nil {
		t.Fatal("expected error, got nil")
	} else {
		for _, e := range expected {
			if !errors.Is(err, e) {
				t.Fatalf("expected error %q not present in %q", e, err)
			}
		}
	}
}

func getClient(t *testing.T, c *configuration) *opaque.Client {
	t.Helper()

	client, err := c.conf.Client()
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	return client
}

func getServer(t *testing.T, c *configuration) *opaque.Server {
	t.Helper()

	server, err := c.conf.Server()
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	return server
}

func setup(t *testing.T, c *configuration) (*opaque.Client, *opaque.Server) {
	t.Helper()

	client := getClient(t, c)
	server := getServer(t, c)
	sks, pks := c.conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		Identity:       serverIdentity,
		PrivateKey:     sks,
		PublicKeyBytes: pks.Encode(),
		OPRFGlobalSeed: c.conf.GenerateOPRFSeed(),
	}

	if err := server.SetKeyMaterial(skm); err != nil {
		t.Fatalf("failed to set server key material: %v", err)
	}

	return client, server
}

func registration(t *testing.T, client *opaque.Client, server *opaque.Server,
	password, credentialIdentifier, clientIdentity, serverIdentity []byte,
) *opaque.ClientRecord {
	t.Helper()

	r1, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}

	r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
	if err != nil {
		t.Fatal(err)
	}

	r3, _, err := client.RegistrationFinalize(r2, clientIdentity, serverIdentity)
	if err != nil {
		t.Fatal(err)
	}

	return &opaque.ClientRecord{
		CredentialIdentifier: credentialIdentifier,
		ClientIdentity:       clientIdentity,
		RegistrationRecord:   r3,
	}
}

func authentication(
	t *testing.T,
	client *opaque.Client,
	password []byte,
	co *opaque.ClientOptions,
	server *opaque.Server,
	so *opaque.ServerOptions,
	record *opaque.ClientRecord,
) (*message.KE1, *message.KE2, *message.KE3, []byte, []byte) {
	t.Helper()

	ke1, err := client.GenerateKE1(password, co)
	if err != nil {
		t.Fatal(err)
	}

	ke2, _, err := server.GenerateKE2(ke1, record, so)
	if err != nil {
		t.Fatal(err)
	}

	ke3, sessionKey, exportKey, err := client.GenerateKE3(ke2, nil, nil, co)
	if err != nil {
		t.Fatal(err)
	}

	return ke1, ke2, ke3, sessionKey, exportKey
}

func testAll(t *testing.T, f func(*testing.T, *configuration)) {
	for _, test := range configurationTable {
		t.Run(test.name, func(t *testing.T) {
			f(t, test)
		})
	}
}

func getBadRistrettoScalar() []byte {
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadRistrettoElement() []byte {
	a := "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBad25519Element() []byte {
	a := "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBad25519Scalar() []byte {
	a := "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000011"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func (c *configuration) getBadScalar() []byte {
	switch c.conf.AKE {
	case opaque.RistrettoSha512:
		return getBadRistrettoScalar()
	default:
		order := c.curve.Params().P
		exceeded := new(big.Int).Add(order, big.NewInt(2)).Bytes()

		err := c.internal.Group.NewScalar().Decode(exceeded)
		if err == nil {
			panic(fmt.Sprintf("Exceeding order did not yield an error for group %s", c.internal.Group))
		}

		return exceeded
	}
}

func (c *configuration) getBadElement() []byte {
	switch c.conf.AKE {
	case opaque.RistrettoSha512:
		return getBadRistrettoElement()
	default:
		size := c.internal.Group.ElementLength()
		element := internal.RandomBytes(size)
		// detag compression
		element[0] = 4

		// test if invalid compression is detected
		err := c.internal.Group.NewElement().Decode(element)
		if err == nil {
			panic(fmt.Sprintf("detagged compressed point did not yield an error for group %s", c.internal.Group))
		}

		return element
	}
}

func (c *configuration) getValidScalar() *ecc.Scalar {
	return c.internal.Group.NewScalar().Random()
}

func (c *configuration) getValidScalarBytes() []byte {
	return c.getValidScalar().Encode()
}

func (c *configuration) getValidElement() *ecc.Element {
	s := c.internal.Group.NewScalar().Random()
	return c.internal.Group.Base().Multiply(s)
}

func (c *configuration) getValidElementBytes() []byte {
	return c.getValidElement().Encode()
}

func buildRecord(t *testing.T,
	conf *configuration,
	credentialIdentifier, password []byte,
) (*opaque.ClientRecord, error) {
	client, server := setup(t, conf)

	r1, err := client.RegistrationInit(password)
	if err != nil {
		return nil, err
	}

	r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
	if err != nil {
		return nil, err
	}

	r3, _, err := client.RegistrationFinalize(r2, nil, nil)
	if err != nil {
		return nil, err
	}

	return &opaque.ClientRecord{
		CredentialIdentifier: credentialIdentifier,
		ClientIdentity:       nil,
		RegistrationRecord:   r3,
	}, nil
}

func xorResponse(c *internal.Configuration, key, nonce, in []byte) []byte {
	pad := c.KDF.Expand(
		key,
		encoding.SuffixString(nonce, tag.CredentialResponsePad),
		c.Group.ElementLength()+c.EnvelopeSize,
	)

	dst := make([]byte, len(pad))

	// if the size is fixed, we could unroll the loop
	for i, r := range pad {
		dst[i] = r ^ in[i]
	}

	return dst
}

func buildPRK(
	conf *internal.Configuration,
	blind *ecc.Scalar,
	password []byte,
	evaluation *ecc.Element,
) ([]byte, error) {
	unblinded := conf.OPRF.Finalize(blind, password, evaluation)
	hardened := conf.KSF.Harden(unblinded, nil, conf.OPRF.Group().ElementLength())

	return conf.KDF.Extract(nil, encoding.Concat(unblinded, hardened)), nil
}

func getEnvelope(
	conf *internal.Configuration,
	blind *ecc.Scalar,
	password []byte,
	ke2 *message.KE2,
) (*keyrecovery.Envelope, []byte, error) {
	randomizedPassword, err := buildPRK(conf, blind, password, ke2.EvaluatedMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	maskingKey := conf.KDF.Expand(randomizedPassword, []byte(tag.MaskingKey), conf.KDF.Size())
	clearText := xorResponse(conf, maskingKey, ke2.MaskingNonce, ke2.MaskedResponse)
	e := clearText[conf.Group.ElementLength():]

	env := &keyrecovery.Envelope{
		Nonce:   e[:conf.NonceLen],
		AuthTag: e[conf.NonceLen:],
	}

	return env, randomizedPassword, nil
}
