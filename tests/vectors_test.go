// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/bytemare/hash"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
)

type ByteToHex []byte

func (j ByteToHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(j))
}

func (j *ByteToHex) UnmarshalJSON(b []byte) error {
	bs := strings.Trim(string(b), "\"")

	dst, err := hex.DecodeString(bs)
	if err != nil {
		return err
	}

	*j = dst
	return nil
}

/*
	Test the test vectors
*/

type config struct {
	Fake    string          `json:"Fake"`
	Group   string          `json:"Group"`
	Hash    string          `json:"Hash"`
	KDF     string          `json:"KDF"`
	MAC     string          `json:"MAC"`
	KSF     string          `json:"KSF"`
	Name    string          `json:"Name"`
	OPRF    oprf.Identifier `json:"OPRF"`
	Context ByteToHex       `json:"Context"`
}

type inputs struct {
	BlindLogin           ByteToHex `json:"blind_login"`
	BlindRegistration    ByteToHex `json:"blind_registration"`
	ClientIdentity       ByteToHex `json:"client_identity,omitempty"`
	ClientKeyshareSeed   ByteToHex `json:"client_keyshare_seed"`
	ClientNonce          ByteToHex `json:"client_nonce"`
	CredentialIdentifier ByteToHex `json:"credential_identifier"`
	EnvelopeNonce        ByteToHex `json:"envelope_nonce"`
	MaskingNonce         ByteToHex `json:"masking_nonce"`
	OprfSeed             ByteToHex `json:"oprf_seed"`
	Password             ByteToHex `json:"password"`
	ServerIdentity       ByteToHex `json:"server_identity,omitempty"`
	ServerKeyshareSeed   ByteToHex `json:"server_keyshare_seed"`
	ServerNonce          ByteToHex `json:"server_nonce"`
	ServerPrivateKey     ByteToHex `json:"server_private_key"`
	ServerPublicKey      ByteToHex `json:"server_public_key"`
	ClientPublicKey      ByteToHex `json:"client_public_key"` // Used for fake credentials tests
	MaskingKey           ByteToHex `json:"masking_key"`       // Used for fake credentials tests
	KE1                  ByteToHex `json:"KE1,omitempty"`     // Used for fake credentials tests
}

type intermediates struct {
	AuthKey         ByteToHex `json:"auth_key"`       //
	ClientMacKey    ByteToHex `json:"client_mac_key"` //
	ClientPublicKey ByteToHex `json:"client_public_key"`
	Envelope        ByteToHex `json:"envelope"`         //
	HandshakeSecret ByteToHex `json:"handshake_secret"` //
	MaskingKey      ByteToHex `json:"masking_key"`
	OprfKey         ByteToHex `json:"oprf_key"`
	RandomPWD       ByteToHex `json:"randomized_pwd"` //
	ServerMacKey    ByteToHex `json:"server_mac_key"` //
}

type outputs struct {
	KE1                  ByteToHex `json:"KE1"`                   //
	KE2                  ByteToHex `json:"KE2"`                   //
	KE3                  ByteToHex `json:"KE3"`                   //
	ExportKey            ByteToHex `json:"export_key"`            //
	RegistrationRequest  ByteToHex `json:"registration_request"`  //
	RegistrationResponse ByteToHex `json:"registration_response"` //
	RegistrationRecord   ByteToHex `json:"registration_upload"`   //
	SessionKey           ByteToHex `json:"session_key"`           //
}

type vector struct {
	Config        config        `json:"config"`
	Inputs        inputs        `json:"inputs"`
	Intermediates intermediates `json:"intermediates"`
	Outputs       outputs       `json:"outputs"`
}

func (v *vector) testRegistration(conf *opaque.Configuration, t *testing.T) {
	// Client
	client, _ := conf.Client()

	g := conf.OPRF.Group()
	blind := g.NewScalar()
	if err := blind.Decode(v.Inputs.BlindRegistration); err != nil {
		panic(err)
	}

	regReq := client.RegistrationInit(v.Inputs.Password, opaque.ClientRegistrationInitOptions{OPRFBlind: blind})

	if !bytes.Equal(v.Outputs.RegistrationRequest, regReq.Serialize()) {
		t.Fatalf(
			"registration requests do not match\nwant: %v\ngot : %v",
			hex.EncodeToString(v.Outputs.RegistrationRequest),
			hex.EncodeToString(regReq.Serialize()),
		)
	}

	// Server
	server, _ := conf.Server()
	pks, err := server.Deserialize.DecodeAkePublicKey(v.Inputs.ServerPublicKey)
	if err != nil {
		panic(err)
	}

	regResp := server.RegistrationResponse(regReq, pks, v.Inputs.CredentialIdentifier, v.Inputs.OprfSeed)

	vRegResp, err := client.Deserialize.RegistrationResponse(v.Outputs.RegistrationResponse)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(vRegResp.EvaluatedMessage.Encode(), regResp.EvaluatedMessage.Encode()) {
		t.Logf("%v\n%v", vRegResp.EvaluatedMessage.Encode(), regResp.EvaluatedMessage.Encode())
		t.Fatal("registration response data do not match")
	}

	if !bytes.Equal(vRegResp.Pks.Encode(), regResp.Pks.Encode()) {
		t.Fatal("registration response serverPublicKey do not match")
	}

	if !bytes.Equal(v.Outputs.RegistrationResponse, regResp.Serialize()) {
		t.Fatal("registration responses do not match")
	}

	// Client
	upload, exportKey := client.RegistrationFinalize(
		regResp,
		opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: v.Inputs.ClientIdentity,
			ServerIdentity: v.Inputs.ServerIdentity,
			EnvelopeNonce:  v.Inputs.EnvelopeNonce,
		},
	)

	if !bytes.Equal(v.Outputs.ExportKey, exportKey) {
		t.Fatalf("exportKey do not match\nexpected %v,\ngot %v", v.Outputs.ExportKey, exportKey)
	}

	if !bytes.Equal(v.Intermediates.Envelope, upload.Envelope) {
		t.Fatalf("envelopes do not match\nexpected %v,\ngot %v", v.Intermediates.Envelope, upload.Envelope)
	}

	if !bytes.Equal(v.Outputs.RegistrationRecord, upload.Serialize()) {
		t.Fatalf("registration upload do not match")
	}
}

func getFakeEnvelope(c *opaque.Configuration) []byte {
	if !hash.Hash(c.MAC).Available() {
		panic(nil)
	}

	envelopeSize := internal.NonceLength + internal.NewMac(c.MAC).Size()

	return make([]byte, envelopeSize)
}

func (v *vector) testLogin(conf *opaque.Configuration, t *testing.T) {
	// Client
	client, _ := conf.Client()

	if !isFake(v.Config.Fake) {
		g := conf.OPRF.Group()
		blind := g.NewScalar()
		if err := blind.Decode(v.Inputs.BlindLogin); err != nil {
			panic(err)
		}

		KE1 := client.GenerateKE1(v.Inputs.Password, opaque.GenerateKE1Options{
			Blind:        blind,
			KeyShareSeed: v.Inputs.ClientKeyshareSeed,
			Nonce:        v.Inputs.ClientNonce,
			NonceLength:  internal.NonceLength,
		})

		if !bytes.Equal(v.Outputs.KE1, KE1.Serialize()) {
			t.Fatalf("KE1 do not match")
		}
	}

	// Server
	server, _ := conf.Server()

	record := &opaque.ClientRecord{}
	if !isFake(v.Config.Fake) {
		upload, err := server.Deserialize.RegistrationRecord(v.Outputs.RegistrationRecord)
		if err != nil {
			t.Fatal(err)
		}

		record.RegistrationRecord = upload
	} else {
		rec, err := server.Deserialize.RegistrationRecord(encoding.Concat3(v.Inputs.ClientPublicKey, v.Inputs.MaskingKey, getFakeEnvelope(conf)))
		if err != nil {
			t.Fatal(err)
		}

		record.RegistrationRecord = rec
	}

	record.CredentialIdentifier = v.Inputs.CredentialIdentifier
	record.ClientIdentity = v.Inputs.ClientIdentity
	record.TestMaskNonce = v.Inputs.MaskingNonce

	v.loginResponse(t, server, record)

	if isFake(v.Config.Fake) {
		return
	}

	// Client
	cke2, err := client.Deserialize.KE2(v.Outputs.KE2)
	if err != nil {
		t.Fatal(err)
	}

	ke3, exportKey, err := client.GenerateKE3(
		cke2,
		opaque.GenerateKE3Options{
			ClientIdentity: v.Inputs.ClientIdentity,
			ServerIdentity: v.Inputs.ServerIdentity,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	//if !bytes.Equal(v.Intermediates.ClientMacKey, client.Ake.ClientMacKey) {
	//	t.Fatal("client mac keys do not match")
	//}

	if !bytes.Equal(v.Outputs.ExportKey, exportKey) {
		t.Fatal("Client export keys do not match")
	}

	if !bytes.Equal(v.Outputs.SessionKey, client.SessionKey()) {
		t.Fatal("Client session keys do not match")
	}

	if !bytes.Equal(v.Outputs.KE3, ke3.Serialize()) {
		t.Fatal("KE3 do not match")
	}

	if err := server.LoginFinish(ke3); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.Outputs.SessionKey, server.SessionKey()) {
		t.Fatal("Server session keys do not match")
	}
}

func oprfToGroup(oprf oprf.Identifier) opaque.Group {
	switch oprf {
	case "ristretto255-SHA512":
		return opaque.RistrettoSha512
	case "P256-SHA256":
		return opaque.P256Sha256
	default:
		return 0
	}
}

func (v *vector) test(t *testing.T) {
	p := &opaque.Configuration{
		OPRF:    oprfToGroup(v.Config.OPRF),
		Hash:    hashToHash(v.Config.Hash),
		KDF:     kdfToHash(v.Config.KDF),
		MAC:     macToHash(v.Config.MAC),
		KSF:     ksfToKSF(v.Config.KSF),
		AKE:     groupToGroup(v.Config.Group),
		Context: []byte(v.Config.Context),
	}

	// Registration
	if !isFake(v.Config.Fake) {
		v.testRegistration(p, t)
	}

	if isFake(v.Config.Fake) {
		v.Outputs.KE1 = v.Inputs.KE1
	}

	// Login
	v.testLogin(p, t)
}

func (v *vector) loginResponse(t *testing.T, s *opaque.Server, record *opaque.ClientRecord) {
	ke1, err := s.Deserialize.KE1(v.Outputs.KE1)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetKeyMaterial(
		v.Inputs.ServerIdentity,
		v.Inputs.ServerPrivateKey,
		v.Inputs.ServerPublicKey,
		v.Inputs.OprfSeed); err != nil {
		t.Fatal(err)
	}

	ke2, err := s.GenerateKE2(
		ke1,
		record,
		opaque.GenerateKE2Options{
			KeyShareSeed: v.Inputs.ServerKeyshareSeed,
			Nonce:        v.Inputs.ServerNonce,
			NonceLength:  internal.NonceLength,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	//if !bytes.Equal(v.Intermediates.HandshakeSecret, s.Ake.HandshakeSecret) {
	//	t.Fatalf("HandshakeSecrets do not match : %v", s.Ake.HandshakeSecret)
	//}

	//if !bytes.Equal(v.Intermediates.ServerMacKey, s.Ake.ServerMacKey) {
	//	t.Fatalf("ServerMacs do not match.expected %v,\ngot %v", v.Intermediates.ServerMacKey, s.Ake.ServerMacKey)
	//}

	//if !bytes.Equal(v.Intermediates.ClientMacKey, s.Ake.Keys.ClientMacKey) {
	//	t.Fatal("ClientMacs do not match")
	//}

	if !isFake(v.Config.Fake) {
		vectorKE3, err := s.Deserialize.KE3(v.Outputs.KE3)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(vectorKE3.ClientMac, s.ExpectedMAC()) {
			t.Fatalf("Expected client MACs do not match : %v", s.ExpectedMAC())
		}

		if !bytes.Equal(v.Outputs.SessionKey, s.SessionKey()) {
			t.Fatalf("Server's session key is invalid : %v", v.Outputs.SessionKey)
		}
	}

	vectorKE2, err := s.Deserialize.KE2(v.Outputs.KE2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(
		vectorKE2.CredentialResponse.EvaluatedMessage.Encode(),
		ke2.CredentialResponse.EvaluatedMessage.Encode(),
	) {
		t.Fatal("data do not match")
	}

	if !bytes.Equal(vectorKE2.CredentialResponse.MaskingNonce, ke2.CredentialResponse.MaskingNonce) {
		t.Fatal("serverPublicKey do not match")
	}

	if !bytes.Equal(vectorKE2.CredentialResponse.MaskedResponse, ke2.CredentialResponse.MaskedResponse) {
		t.Fatal("MaskedResponse do not match")
	}

	if !bytes.Equal(vectorKE2.CredentialResponse.Serialize(), ke2.CredentialResponse.Serialize()) {
		t.Fatal("CredResp do not match")
	}

	if !bytes.Equal(vectorKE2.ServerNonce, ke2.ServerNonce) {
		t.Fatal("nonces do not match")
	}

	if !bytes.Equal(vectorKE2.ServerPublicKeyshare.Encode(), ke2.ServerPublicKeyshare.Encode()) {
		t.Fatal("epks do not match")
	}

	if !bytes.Equal(vectorKE2.ServerMac, ke2.ServerMac) {
		t.Fatalf("server macs do not match")
	}

	if !bytes.Equal(v.Outputs.KE2, ke2.Serialize()) {
		t.Fatalf("KE2 do not match")
	}

	if !isFake(v.Config.Fake) && !bytes.Equal(v.Outputs.SessionKey, s.Ake.SessionKey()) {
		t.Fatalf("Server SessionKey do not match:\n%v\n%v", v.Outputs.SessionKey, s.Ake.SessionKey())
	}
}

func isFake(f string) bool {
	switch f {
	case "True":
		return true
	case "False":
		return false
	default:
		panic("'Fake' parameter not recognised")
	}
}

func hashToHash(h string) crypto.Hash {
	switch h {
	case "SHA256":
		return crypto.SHA256
	case "SHA512":
		return crypto.SHA512
	default:
		return 0
	}
}

func kdfToHash(h string) crypto.Hash {
	switch h {
	case "HKDF-SHA256":
		return crypto.SHA256
	case "HKDF-SHA512":
		return crypto.SHA512
	default:
		return 0
	}
}

func macToHash(h string) crypto.Hash {
	switch h {
	case "HMAC-SHA256":
		return crypto.SHA256
	case "HMAC-SHA512":
		return crypto.SHA512
	default:
		return 0
	}
}

func ksfToKSF(h string) ksf.Identifier {
	switch h {
	case "Identity":
		return 0
	case "Scrypt":
		return ksf.Scrypt
	default:
		return 0
	}
}

func groupToGroup(g string) opaque.Group {
	switch g {
	case "ristretto255":
		return opaque.RistrettoSha512
	case "decaf448":
		panic("group not supported")
	case "P256_XMD:SHA-256_SSWU_RO_":
		return opaque.P256Sha256
	case "P384_XMD:SHA-384_SSWU_RO_":
		return opaque.P384Sha512
	case "P521_XMD:SHA-512_SSWU_RO_":
		return opaque.P521Sha512
	// case "curve25519_XMD:SHA-512_ELL2_RO_":
	//	return opaque.Curve25519Sha512
	default:
		log.Printf("group %s", g)
		panic("group not recognised")
	}
}

type draftVectors []*vector

func loadOpaqueVectors(filepath string) (draftVectors, error) {
	contents, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}

	var v draftVectors
	errJSON := json.Unmarshal(contents, &v)
	if errJSON != nil {
		return nil, errJSON
	}

	return v, nil
}

func TestOpaqueVectors(t *testing.T) {
	vectorFile := "vectors.json"

	v, err := loadOpaqueVectors(vectorFile)
	if err != nil || v == nil {
		t.Fatal(err)
	}

	for _, tv := range v {
		if tv.Config.Group == "curve25519" {
			continue
		}
		t.Run(fmt.Sprintf("%s - %s - Fake:%s", tv.Config.Name, tv.Config.Group, tv.Config.Fake), tv.test)
	}
}
