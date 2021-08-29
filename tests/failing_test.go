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

	"github.com/bytemare/crypto/mhf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	message2 "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var (
	errInvalidMessageLength = errors.New("invalid message length")
	errInvalidStateLength   = errors.New("invalid state length")
	errStateExists          = errors.New("existing state is not empty")
)

func TestDeserializeRegistrationRequest(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server := c.Server()
	length := server.OPRFPointLength + 1
	if _, err := server.DeserializeRegistrationRequest(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeRegistrationRequest(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationResponse(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server := c.Server()
	length := server.OPRFPointLength + server.AkePointLength + 1
	if _, err := server.DeserializeRegistrationResponse(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeRegistrationResponse(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationRecord(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server := c.Server()
	length := server.AkePointLength + server.Hash.Size() + server.EnvelopeSize + 1
	if _, err := server.DeserializeRegistrationRecord(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeRegistrationRecord(internal.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE1(t *testing.T) {
	c := opaque.DefaultConfiguration()
	group := group.Group(c.AKE)
	ke1Length := encoding.PointLength[group] + internal.NonceLength + encoding.PointLength[group]

	server := c.Server()
	if _, err := server.DeserializeKE1(internal.RandomBytes(ke1Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeKE1(internal.RandomBytes(ke1Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE2(t *testing.T) {
	c := opaque.DefaultConfiguration()

	client := c.Client()
	ke2Length := client.OPRFPointLength + 2*client.NonceLen + 2*client.AkePointLength + client.EnvelopeSize + client.MAC.Size()
	if _, err := client.DeserializeKE2(internal.RandomBytes(ke2Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	server := c.Server()
	ke2Length = server.OPRFPointLength + 2*server.NonceLen + 2*server.AkePointLength + server.EnvelopeSize + server.MAC.Size()
	if _, err := server.DeserializeKE2(internal.RandomBytes(ke2Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE3(t *testing.T) {
	c := opaque.DefaultConfiguration()
	ke3Length := c.MAC.Size()

	server := c.Server()
	if _, err := server.DeserializeKE3(internal.RandomBytes(ke3Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
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
		MHF:             internal.NewMHF(def.MHF),
		NonceLen:        internal.NonceLength,
		OPRFPointLength: encoding.PointLength[g],
		AkePointLength:  encoding.PointLength[g],
		Group:           g,
		OPRF:            oprf.Ciphersuite(g),
		Context:         def.Context,
	}

	s := opaque.NewServer(nil)
	if reflect.DeepEqual(s.Parameters, defaultConfiguration) {
		t.Errorf("server did not default to correct configuration")
	}

	c := opaque.NewClient(nil)
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
			MHF:  mhf.Scrypt,
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
			MHF:  mhf.Scrypt,
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
			MHF:  mhf.Scrypt,
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
	//		MHF:  mhf.Scrypt,
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
		return getBadNistElement(t, oprf.Ciphersuite(c.Conf.AKE).Group())
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

func buildRecord(t *testing.T, credID, oprfSeed, password, pks []byte, client *opaque.Client, server *opaque.Server) *opaque.ClientRecord {
	r1 := client.RegistrationInit(password)
	r2, err := server.RegistrationResponse(r1, pks, credID, oprfSeed)
	if err != nil {
		t.Fatal(err)
	}

	r3, _, err := client.RegistrationFinalize(&opaque.Credentials{}, r2)
	if err != nil {
		t.Fatal(err)
	}

	return &opaque.ClientRecord{
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
		RegistrationRecord:   r3,
		TestMaskNonce:        nil,
	}
}

func buildPRK(client *opaque.Client, evaluation []byte) ([]byte, error) {
	unblinded, err := client.OPRF.Finalize(evaluation)
	if err != nil {
		return nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	hardened := client.MHF.Harden(unblinded, nil, client.OPRFPointLength)

	return client.KDF.Extract(nil, hardened), nil
}

func getEnvelope(client *opaque.Client, ke2 *message.KE2) (*keyrecovery.Envelope, []byte, error) {
	randomizedPwd, err := buildPRK(client, ke2.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	maskingKey := client.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), client.Hash.Size())

	clear := client.MaskResponse(maskingKey, ke2.MaskingNonce, ke2.MaskedResponse)
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
	credId := internal.RandomBytes(32)
	seed := internal.RandomBytes(32)
	terr := " RegistrationResponse: can't evaluate input : "

	for i, e := range confs {
		badRequest := &message.RegistrationRequest{Data: getBadElement(t, e)}
		server := e.Conf.Server()
		if _, err := server.RegistrationResponse(badRequest, nil, credId, seed); err == nil || !strings.HasPrefix(err.Error(), terr) {
			t.Fatalf("#%d - expected error. Got %v", i, err)
		}
	}
}

func TestServerInit_InvalidPublicKey(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	for _, conf := range confs {
		server := conf.Conf.Server()
		expected := "invalid server public key: "

		if _, err := server.Init(nil, nil, nil, nil, nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil pubkey - got %s", err)
		}

		if _, err := server.Init(nil, nil, nil, getBadElement(t, conf), nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad secret key - got %s", err)
		}
	}
}

func TestServerInit_NilSecretKey(t *testing.T) {
	/*
		Nil server secret key
	*/
	for _, conf := range confs {
		server := conf.Conf.Server()
		_, pk := server.KeyGen()
		expected := "invalid server secret key: "

		if _, err := server.Init(nil, nil, nil, pk, nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidData(t *testing.T) {
	/*
		Invalid OPRF data in KE1
	*/
	seed := internal.RandomBytes(32)
	rec := &opaque.ClientRecord{
		CredentialIdentifier: internal.RandomBytes(32),
		ClientIdentity:       nil,
		RegistrationRecord: &message.RegistrationRecord{
			MaskingKey: internal.RandomBytes(32),
		},
		TestMaskNonce: nil,
	}

	for _, conf := range confs {
		server := conf.Conf.Server()
		sk, pk := server.KeyGen()
		client := conf.Conf.Client()
		ke1 := client.Init([]byte("yo"))
		ke1.CredentialRequest.Data = getBadElement(t, conf)
		expected := " credentialResponse: oprfResponse: can't evaluate input :"
		if _, err := server.Init(ke1, nil, sk, pk, seed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad oprf request - got %s", err)
		}
	}
}

func TestServerInit_InvalidEPKU(t *testing.T) {
	/*
		Invalid EPKU in KE1
	*/
	seed := internal.RandomBytes(32)
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
		server := conf.Conf.Server()
		sk, pk := server.KeyGen()
		client := conf.Conf.Client()
		ke1 := client.Init([]byte("yo"))
		ke1.EpkU = getBadElement(t, conf)
		expected := " AKE response: decoding peer ephemeral public key:"
		if _, err := server.Init(ke1, nil, sk, pk, seed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad epku - got %s", err)
		}
	}
}

func TestServerInit_InvalidPKU(t *testing.T) {
	/*
		Invalid PKU in KE1
	*/
	seed := internal.RandomBytes(32)
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
		server := conf.Conf.Server()
		sk, pk := server.KeyGen()
		client := conf.Conf.Client()
		ke1 := client.Init([]byte("yo"))
		rec.PublicKey = getBadElement(t, conf)
		expected := " AKE response: decoding peer public key:"
		if _, err := server.Init(ke1, nil, sk, pk, seed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
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
	seed := internal.RandomBytes(32)
	client := conf.Client()
	server := conf.Server()
	sk, pk := server.KeyGen()
	rec := buildRecord(t, credId, seed, []byte("yo"), pk, client, server)
	ke1 := client.Init([]byte("yo"))
	ke2, _ := server.Init(ke1, nil, sk, pk, seed, rec)
	ke3, _, _ := client.Finish(nil, nil, ke2)
	ke3.Mac[0] = ^ke3.Mac[0]

	expected := opaque.ErrAkeInvalidClientMac
	if err := server.Finish(ke3); err == nil || err.Error() != expected.Error() {
		t.Fatalf("expected error on invalid mac - got %v", err)
	}
}

func TestServerSetAKEState_InvalidInput(t *testing.T) {
	conf := opaque.DefaultConfiguration()

	/*
		Test an invalid state
	*/

	buf := internal.RandomBytes(conf.MAC.Size() + conf.KDF.Size() + 1)

	server := conf.Server()
	if err := server.SetAKEState(buf); err == nil || err.Error() != errInvalidStateLength.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errInvalidStateLength, err)
	}

	/*
		A state already exists.
	*/

	credId := internal.RandomBytes(32)
	seed := internal.RandomBytes(32)
	client := conf.Client()
	server = conf.Server()
	sk, pk := server.KeyGen()
	rec := buildRecord(t, credId, seed, []byte("yo"), pk, client, server)
	ke1 := client.Init([]byte("yo"))
	_, _ = server.Init(ke1, nil, sk, pk, seed, rec)
	state := server.SerializeState()
	if err := server.SetAKEState(state); err == nil || err.Error() != errStateExists.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errStateExists, err)
	}
}

// client.go

func TestClientRegistrationFinalize_InvalidPks(t *testing.T) {
	/*
		Empty and invalid server public key sent to client
	*/
	credID := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		_, pks := server.KeyGen()
		r1 := client.RegistrationInit([]byte("yo"))

		r2, err := server.RegistrationResponse(r1, pks, credID, oprfSeed)
		if err != nil {
			t.Fatal(err)
		}

		// nil pks
		r2.Pks = nil
		expected := "invalid server public key :"
		if _, _, err := client.RegistrationFinalize(&opaque.Credentials{}, r2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid server public key - got %v", err)
		}

		// nil pks
		r2.Pks = getBadElement(t, conf)
		if _, _, err := client.RegistrationFinalize(&opaque.Credentials{}, r2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid server public key - got %v", err)
		}
	}
}

func TestClientRegistrationFinalize_InvalidEvaluation(t *testing.T) {
	/*
		Oprf finalize - evaluation deserialization // element decoding
	*/
	for _, conf := range confs {
		client := conf.Conf.Client()
		badr2 := &message.RegistrationResponse{
			Data: getBadElement(t, conf),
			Pks:  client.Group.Base().Bytes(),
		}

		expected := "finalizing OPRF : could not decode element :"
		if _, _, err := client.RegistrationFinalize(&opaque.Credentials{}, badr2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid evualuated element - got %v", err)
		}
	}
}

func TestClientFinish_BadEvaluation(t *testing.T) {
	/*
		Oprf finalize : evaluation deserialization // element decoding
	*/
	for _, conf := range confs {
		client := conf.Conf.Client()
		_ = client.Init([]byte("yo"))
		ke2 := &message.KE2{
			CredentialResponse: &message2.CredentialResponse{
				Data:           getBadElement(t, conf),
				MaskedResponse: internal.RandomBytes(encoding.PointLength[client.Group] + client.EnvelopeSize),
			},
		}

		expected := "finalizing OPRF : could not decode element :"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid evaluated element - got %v", err)
		}
	}
}

func TestClientFinish_BadMaskedResponse(t *testing.T) {
	/*
		The masked response is of invalid length.
	*/
	credID := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)

		goodLength := encoding.PointLength[client.Group] + client.EnvelopeSize
		expected := "invalid masked response length"

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for short response - got %v", err)
		}

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for long response - got %v", err)
		}
	}
}

func TestClientFinish_InvalidEnvelopeTag(t *testing.T) {
	/*
		Invalid envelope tag
	*/
	credID := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)

		env, _, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(client.MAC.Size())
		clear := encoding.Concat(pks, env.Serialize())
		ke2.MaskedResponse = server.MaskResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		// too short
		expected := "recover envelope: invalid envelope authentication tag"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
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
		Invalid envelope tag
	*/
	credID := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)
		epks := ke2.EpkS

		// tamper epks
		ke2.EpkS = getBadElement(t, conf)
		expected := " AKE finalization: decoding peer ephemeral public key:"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}

		// tamper PKS
		ke2.EpkS = epks
		env, randomizedPwd, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		badpks := getBadElement(t, conf)

		ctc := cleartextCredentials(rec.RegistrationRecord.PublicKey, badpks, nil, nil)
		authKey := client.KDF.Expand(randomizedPwd, encoding.SuffixString(env.Nonce, tag.AuthKey), client.KDF.Size())
		authTag := client.MAC.MAC(authKey, encoding.Concat(env.Nonce, ctc))
		env.AuthTag = authTag

		clear := encoding.Concat(badpks, env.Serialize())
		ke2.MaskedResponse = server.MaskResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = " AKE finalization: decoding peer public key:"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}
	}
}

func TestClientFinish_InvalidKE2Mac(t *testing.T) {
	/*
		Invalid server ke2 mac
	*/
	credID := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)

		ke2.Mac = internal.RandomBytes(client.MAC.Size())
		expected := " AKE finalization: invalid server mac"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}
	}
}
