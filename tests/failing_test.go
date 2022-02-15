// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"crypto"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/bytemare/crypto/group"
	"github.com/bytemare/crypto/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	errInvalidMessageLength = errors.New("invalid message length for the configuration")
	errInvalidStateLength   = errors.New("invalid state length")
	errStateExists          = errors.New("existing state is not empty")
)

func TestDeserializeRegistrationRequest(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server, _ := c.Server()
	length := server.OPRFPointLength + 1
	if _, err := server.DeserializeRegistrationRequest(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.DeserializeRegistrationRequest(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationResponse(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server, _ := c.Server()
	length := server.OPRFPointLength + server.AkePointLength + 1
	if _, err := server.DeserializeRegistrationResponse(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.DeserializeRegistrationResponse(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationRecord(t *testing.T) {
	for _, e := range confs {
		server, _ := e.Conf.Server()
		length := server.AkePointLength + server.Hash.Size() + server.EnvelopeSize + 1
		if _, err := server.DeserializeRegistrationRecord(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
		}

		badPKu := getBadElement(t, e)
		rec := encoding.Concat(badPKu, internal.RandomBytes(server.Hash.Size()+server.EnvelopeSize))

		expect := "invalid client public key"
		if _, err := server.DeserializeRegistrationRecord(rec); err == nil || err.Error() != expect {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", expect, err)
		}

		client, _ := e.Conf.Client()
		if _, err := client.DeserializeRecord(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
		}
	}
}

func TestDeserializeKE1(t *testing.T) {
	c := opaque.DefaultConfiguration()
	g := group.Group(c.AKE)
	ke1Length := encoding.PointLength[g] + internal.NonceLength + encoding.PointLength[g]

	server, _ := c.Server()
	if _, err := server.DeserializeKE1(internal.RandomBytes(ke1Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.DeserializeKE1(internal.RandomBytes(ke1Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE2(t *testing.T) {
	c := opaque.DefaultConfiguration()

	client, _ := c.Client()
	ke2Length := client.OPRFPointLength + 2*client.NonceLen + 2*client.AkePointLength + client.EnvelopeSize + client.MAC.Size()
	if _, err := client.DeserializeKE2(internal.RandomBytes(ke2Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	server, _ := c.Server()
	ke2Length = server.OPRFPointLength + 2*server.NonceLen + 2*server.AkePointLength + server.EnvelopeSize + server.MAC.Size()
	if _, err := server.DeserializeKE2(internal.RandomBytes(ke2Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE3(t *testing.T) {
	c := opaque.DefaultConfiguration()
	ke3Length := c.MAC.Size()

	server, _ := c.Server()
	if _, err := server.DeserializeKE3(internal.RandomBytes(ke3Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.DeserializeKE3(internal.RandomBytes(ke3Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

// opaque.go

func TestDeserializeConfiguration_Short(t *testing.T) {
	r9 := internal.RandomBytes(7)

	if _, err := opaque.DeserializeConfiguration(r9); !errors.Is(err, internal.ErrConfigurationInvalidLength) {
		t.Errorf("DeserializeConfiguration did not return the appropriate error for vector r9. want %q, got %q",
			internal.ErrConfigurationInvalidLength, err)
	}
}

func TestDeserializeConfiguration_InvalidContextHeader(t *testing.T) {
	d := opaque.DefaultConfiguration().Serialize()
	d[7] = 3

	expected := "decoding the configuration context: "
	if _, err := opaque.DeserializeConfiguration(d); err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Errorf("DeserializeConfiguration did not return the appropriate error for vector invalid header. want %q, got %q",
			expected, err)
	}
}

func TestNilConfiguration(t *testing.T) {
	def := opaque.DefaultConfiguration()
	g := group.Group(def.AKE)
	defaultConfiguration := &internal.Parameters{
		KDF:             internal.NewKDF(def.KDF),
		MAC:             internal.NewMac(def.MAC),
		Hash:            internal.NewHash(def.Hash),
		KSF:             internal.NewKSF(def.KSF),
		NonceLen:        internal.NonceLength,
		OPRFPointLength: encoding.PointLength[g],
		AkePointLength:  encoding.PointLength[g],
		Group:           g,
		OPRF:            oprf.Ciphersuite(g),
		Context:         def.Context,
	}

	s, _ := opaque.NewServer(nil)
	if reflect.DeepEqual(s.Parameters, defaultConfiguration) {
		t.Errorf("server did not default to correct configuration")
	}

	c, _ := opaque.NewClient(nil)
	if reflect.DeepEqual(c.Parameters, defaultConfiguration) {
		t.Errorf("client did not default to correct configuration")
	}
}

// helper functions

type configuration struct {
	Conf  *opaque.Configuration
	Curve elliptic.Curve
}

var confs = []configuration{
	{
		Conf:  opaque.DefaultConfiguration(),
		Curve: nil,
	},
	{
		Conf: &opaque.Configuration{
			OPRF: opaque.P256Sha256,
			KDF:  crypto.SHA256,
			MAC:  crypto.SHA256,
			Hash: crypto.SHA256,
			KSF:  ksf.Scrypt,
			AKE:  opaque.P256Sha256,
		},
		Curve: elliptic.P256(),
	},
	{
		Conf: &opaque.Configuration{
			OPRF: opaque.P384Sha512,
			KDF:  crypto.SHA512,
			MAC:  crypto.SHA512,
			Hash: crypto.SHA512,
			KSF:  ksf.Scrypt,
			AKE:  opaque.P384Sha512,
		},
		Curve: elliptic.P384(),
	},
	{
		Conf: &opaque.Configuration{
			OPRF: opaque.P521Sha512,
			KDF:  crypto.SHA512,
			MAC:  crypto.SHA512,
			Hash: crypto.SHA512,
			KSF:  ksf.Scrypt,
			AKE:  opaque.P521Sha512,
		},
		Curve: elliptic.P521(),
	},
	//{
	//	Conf: &opaque.Configuration{
	//		OPRF: opaque.RistrettoSha512,
	//		KDF:  crypto.SHA512,
	//		MAC:  crypto.SHA512,
	//		Hash: crypto.SHA512,
	//		KSF:  ksf.Scrypt,
	//		Mode: opaque.Internal,
	//		AKE:  opaque.Curve25519Sha512,
	//	},
	//	Curve: nil,
	//},
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

func badScalar(t *testing.T, ci group.Group, curve elliptic.Curve) []byte {
	order := curve.Params().P
	exceeded := new(big.Int).Add(order, big.NewInt(2)).Bytes()

	_, err := ci.NewScalar().Decode(exceeded)
	if err == nil {
		t.Errorf("Exceeding order did not yield an error for group %s", ci)
	}

	return exceeded
}

func getBadNistElement(t *testing.T, id group.Group) []byte {
	size := encoding.PointLength[id]
	element := internal.RandomBytes(size)
	// detag compression
	element[0] = 4

	// test if invalid compression is detected
	_, err := id.NewElement().Decode(element)
	if err == nil {
		t.Errorf("detagged compressed point did not yield an error for group %s", id)
	}

	return element
}

func getBadElement(t *testing.T, c configuration) []byte {
	switch c.Conf.AKE {
	case opaque.RistrettoSha512:
		return getBadRistrettoElement()
	// case opaque.Curve25519Sha512:
	//	return getBad25519Element()
	default:
		return getBadNistElement(t, group.Group(c.Conf.AKE))
	}
}

func getBadScalar(t *testing.T, c configuration) []byte {
	switch c.Conf.AKE {
	case opaque.RistrettoSha512:
		return getBadRistrettoScalar()
	// case opaque.Curve25519Sha512:
	//	return getBad25519Scalar()
	default:
		return badScalar(t, oprf.Ciphersuite(c.Conf.AKE).Group(), c.Curve)
	}
}

func buildRecord(credID, oprfSeed, password, pks []byte, client *opaque.Client, server *opaque.Server) *opaque.ClientRecord {
	r1 := client.RegistrationInit(password)
	pk, err := server.Group.NewElement().Decode(pks)
	if err != nil {
		panic(err)
	}
	r2 := server.RegistrationResponse(r1, pk, credID, oprfSeed)
	r3, _ := client.RegistrationFinalize(&opaque.Credentials{}, r2)

	return &opaque.ClientRecord{
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
		RegistrationRecord:   r3,
		TestMaskNonce:        nil,
	}
}

func buildPRK(client *opaque.Client, evaluation *group.Point) ([]byte, error) {
	unblinded := client.OPRF.Finalize(evaluation)
	hardened := client.KSF.Harden(unblinded, nil, client.OPRFPointLength)

	return client.KDF.Extract(nil, hardened), nil
}

func getEnvelope(client *opaque.Client, ke2 *message.KE2) (*keyrecovery.Envelope, []byte, error) {
	randomizedPwd, err := buildPRK(client, ke2.EvaluatedMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	maskingKey := client.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), client.Hash.Size())

	clear := client.XorResponse(maskingKey, ke2.MaskingNonce, ke2.MaskedResponse)
	e := clear[encoding.PointLength[client.Group]:]

	env := &keyrecovery.Envelope{
		Nonce:   e[:client.NonceLen],
		AuthTag: e[client.NonceLen:],
	}

	return env, randomizedPwd, nil
}

// server.go

func TestServer_BadRegistrationRequest(t *testing.T) {
	/*
		Error in OPRF
		- client blinded element invalid point encoding
	*/
	err1 := "invalid message length"
	err2 := "blinded data is an invalid point"

	for i, e := range confs {
		server, _ := e.Conf.Server()
		if _, err := server.DeserializeRegistrationRequest(nil); err == nil || !strings.HasPrefix(err.Error(), err1) {
			t.Fatalf("#%d - expected error. Got %v", i, err)
		}

		bad := getBadElement(t, e)
		if _, err := server.DeserializeRegistrationRequest(bad); err == nil || !strings.HasPrefix(err.Error(), err2) {
			t.Fatalf("#%d - expected error. Got %v", i, err)
		}
	}
}

func TestServerInit_InvalidPublicKey(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		sk, _ := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())

		expected := "input server public key's length is invalid"
		if _, err := server.LoginInit(nil, nil, sk, nil, oprfSeed, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil pubkey - got %s", err)
		}

		expected = "invalid server public key: "
		if _, err := server.LoginInit(nil, nil, sk, getBadElement(t, conf), oprfSeed, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidOPRFSeedLength(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		sk, pk := server.KeyGen()
		expected := opaque.ErrInvalidOPRFSeedLength

		if _, err := server.LoginInit(nil, nil, sk, pk, nil, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on nil seed - got %s", err)
		}

		seed := internal.RandomBytes(conf.Conf.Hash.Size() - 1)
		if _, err := server.LoginInit(nil, nil, sk, pk, seed, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on bad seed - got %s", err)
		}

		seed = internal.RandomBytes(conf.Conf.Hash.Size() + 1)
		if _, err := server.LoginInit(nil, nil, sk, pk, seed, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on bad seed - got %s", err)
		}
	}
}

func TestServerInit_NilSecretKey(t *testing.T) {
	/*
		Nil server secret key
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		_, pk := server.KeyGen()
		expected := "invalid server secret key: "

		if _, err := server.LoginInit(nil, nil, nil, pk, nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidEnvelope(t *testing.T) {
	/*
		Record envelope of invalid length
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		sk, pk := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		client, _ := conf.Conf.Client()
		rec := buildRecord(internal.RandomBytes(32), oprfSeed, []byte("yo"), pk, client, server)
		rec.Envelope = internal.RandomBytes(15)

		expected := "record has invalid envelope length"
		if _, err := server.LoginInit(nil, nil, sk, pk, oprfSeed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidData(t *testing.T) {
	/*
		Invalid OPRF data in KE1
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		ke1 := encoding.Concatenate(getBadElement(t, conf), internal.RandomBytes(server.Parameters.NonceLen), internal.RandomBytes(server.Parameters.AkePointLength))
		expected := "blinded data is an invalid point"
		if _, err := server.DeserializeKE1(ke1); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad oprf request - got %s", err)
		}
	}
}

func TestServerInit_InvalidEPKU(t *testing.T) {
	/*
		Invalid EPKU in KE1
	*/
	rec := &opaque.ClientRecord{
		CredentialIdentifier: internal.RandomBytes(32),
		ClientIdentity:       nil,
		RegistrationRecord: &message.RegistrationRecord{
			MaskingKey: internal.RandomBytes(32),
		},
		TestMaskNonce: nil,
	}

	for _, conf := range confs {
		rec.Envelope = opaque.GetFakeEnvelope(conf.Conf)
		server, _ := conf.Conf.Server()
		client, _ := conf.Conf.Client()
		ke1 := client.LoginInit([]byte("yo")).Serialize()
		badke1 := encoding.Concat(ke1[:server.Parameters.OPRFPointLength+server.Parameters.NonceLen], getBadElement(t, conf))
		expected := "invalid ephemeral client public key"
		if _, err := server.DeserializeKE1(badke1); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad epku - got %s", err)
		}
	}
}

func TestServerFinish_InvalidKE3Mac(t *testing.T) {
	/*
		ke3 mac is invalid
	*/
	conf := opaque.DefaultConfiguration()
	credId := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ := conf.Server()
	sk, pk := server.KeyGen()
	rec := buildRecord(credId, oprfSeed, []byte("yo"), pk, client, server)
	ke1 := client.LoginInit([]byte("yo"))
	ke2, err := server.LoginInit(ke1, nil, sk, pk, oprfSeed, rec)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, err := client.LoginFinish(nil, nil, ke2)
	if err != nil {
		t.Fatal(err)
	}
	ke3.Mac[0] = ^ke3.Mac[0]

	expected := opaque.ErrAkeInvalidClientMac
	if err := server.LoginFinish(ke3); err == nil || err.Error() != expected.Error() {
		t.Fatalf("expected error on invalid mac - got %v", err)
	}
}

func TestServerSetAKEState_InvalidInput(t *testing.T) {
	conf := opaque.DefaultConfiguration()

	/*
		Test an invalid state
	*/

	buf := internal.RandomBytes(conf.MAC.Size() + conf.KDF.Size() + 1)

	server, _ := conf.Server()
	if err := server.SetAKEState(buf); err == nil || err.Error() != errInvalidStateLength.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errInvalidStateLength, err)
	}

	/*
		A state already exists.
	*/

	credId := internal.RandomBytes(32)
	seed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ = conf.Server()
	sk, pk := server.KeyGen()
	rec := buildRecord(credId, seed, []byte("yo"), pk, client, server)
	ke1 := client.LoginInit([]byte("yo"))
	_, _ = server.LoginInit(ke1, nil, sk, pk, seed, rec)
	state := server.SerializeState()
	if err := server.SetAKEState(state); err == nil || err.Error() != errStateExists.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errStateExists, err)
	}
}

// client.go
func TestClientRegistrationFinalize_InvalidPks(t *testing.T) {
	/*
		Invalid data sent to the client
	*/
	credID := internal.RandomBytes(32)

	for _, conf := range confs {
		client, _ := conf.Conf.Client()
		server, _ := conf.Conf.Server()
		_, pks := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		r1 := client.RegistrationInit([]byte("yo"))

		pk, err := server.Group.NewElement().Decode(pks)
		if err != nil {
			panic(err)
		}
		r2 := server.RegistrationResponse(r1, pk, credID, oprfSeed)

		// message length
		badr2 := internal.RandomBytes(15)
		expected := "invalid message length"
		if _, err := client.DeserializeRegistrationResponse(badr2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for empty server public key - got %v", err)
		}

		// invalid data
		badr2 = encoding.Concat(getBadElement(t, conf), pks)
		expected = "invalid OPRF evaluation"
		if _, err := client.DeserializeRegistrationResponse(badr2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for empty server public key - got %v", err)
		}

		// nil pks
		expected = "invalid server public key"
		badr2 = encoding.Concat(r2.Serialize()[:client.OPRFPointLength], getBadElement(t, conf))
		if _, err := client.DeserializeRegistrationResponse(badr2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid server public key - got %v", err)
		}
	}
}

func TestClientFinish_BadEvaluation(t *testing.T) {
	/*
		Oprf finalize : evaluation deserialization // element decoding
	*/
	for _, conf := range confs {
		client, _ := conf.Conf.Client()
		_ = client.LoginInit([]byte("yo"))
		r2 := encoding.Concat(getBadElement(t, conf), internal.RandomBytes(client.NonceLen+client.AkePointLength+client.EnvelopeSize))
		badKe2 := encoding.Concat(r2, internal.RandomBytes(client.NonceLen+client.AkePointLength+client.MAC.Size()))

		expected := "invalid OPRF evaluation"
		if _, err := client.DeserializeKE2(badKe2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid evaluated element - got %v", err)
		}
	}
}

func TestClientFinish_BadMaskedResponse(t *testing.T) {
	/*
		The masked response is of invalid length.
	*/
	credID := internal.RandomBytes(32)

	for _, conf := range confs {
		client, _ := conf.Conf.Client()
		server, _ := conf.Conf.Server()
		sks, pks := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)

		goodLength := encoding.PointLength[client.Group] + client.EnvelopeSize
		expected := "invalid masked response length"

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for short response - got %v", err)
		}

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for long response - got %v", err)
		}
	}
}

func TestClientFinish_InvalidEnvelopeTag(t *testing.T) {
	/*
		Invalid envelope tag
	*/
	credID := internal.RandomBytes(32)

	for _, conf := range confs {
		client, _ := conf.Conf.Client()
		server, _ := conf.Conf.Server()
		sks, pks := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)

		env, _, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(client.MAC.Size())
		clear := encoding.Concat(pks, env.Serialize())
		ke2.MaskedResponse = server.XorResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		// too short
		expected := "recover envelope: invalid envelope authentication tag"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid envelope mac - got %v", err)
		}
	}
}

func cleartextCredentials(clientPublicKey, serverPublicKey, idc, ids []byte) []byte {
	if ids == nil {
		ids = serverPublicKey
	}

	if idc == nil {
		idc = clientPublicKey
	}

	return encoding.Concat3(serverPublicKey, encoding.EncodeVector(ids), encoding.EncodeVector(idc))
}

func TestClientFinish_InvalidKE2KeyEncoding(t *testing.T) {
	/*
		Tamper KE2 values
	*/
	credID := internal.RandomBytes(32)

	for _, conf := range confs {
		client, _ := conf.Conf.Client()
		server, _ := conf.Conf.Server()
		sks, pks := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)
		// epks := ke2.EpkS

		// tamper epks
		offset := client.AkePointLength + client.MAC.Size()
		encoded := ke2.Serialize()
		badKe2 := encoding.Concat3(encoded[:len(encoded)-offset], getBadElement(t, conf), ke2.Mac)
		expected := "invalid ephemeral server public key"
		if _, err := client.DeserializeKE2(badKe2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}

		// tamper PKS
		// ke2.EpkS = server.Group.NewElement().Mult(server.Group.NewScalar().Random())
		env, randomizedPwd, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		badpks := getBadElement(t, conf)

		ctc := cleartextCredentials(encoding.SerializePoint(rec.RegistrationRecord.PublicKey, client.Group), badpks, nil, nil)
		authKey := client.KDF.Expand(randomizedPwd, encoding.SuffixString(env.Nonce, tag.AuthKey), client.KDF.Size())
		authTag := client.MAC.MAC(authKey, encoding.Concat(env.Nonce, ctc))
		env.AuthTag = authTag

		clear := encoding.Concat(badpks, env.Serialize())
		ke2.MaskedResponse = server.XorResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = "invalid server public key"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid envelope mac - got %q", err)
		}

		// replace PKS
		fakepks := server.Group.Base().Mult(server.Group.NewScalar().Random()).Bytes()
		clear = encoding.Concat(fakepks, env.Serialize())
		ke2.MaskedResponse = server.XorResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = "recover envelope: invalid envelope authentication tag"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid envelope mac - got %q", err)
		}
	}
}

func TestClientFinish_InvalidKE2Mac(t *testing.T) {
	/*
		Invalid server ke2 mac
	*/
	credID := internal.RandomBytes(32)

	for _, conf := range confs {
		client, _ := conf.Conf.Client()
		server, _ := conf.Conf.Server()
		sks, pks := server.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)

		ke2.Mac = internal.RandomBytes(client.MAC.Size())
		expected := " AKE finalization: invalid server mac"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}
	}
}
