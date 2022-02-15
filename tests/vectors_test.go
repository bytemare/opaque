// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/crypto/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/message"
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
	Test test vectors
*/

type config struct {
	Context ByteToHex `json:"Context"`
	// EnvelopeMode string    `json:"EnvelopeMode"`
	Fake  string    `json:"Fake"`
	Group string    `json:"Group"`
	Hash  string    `json:"Hash"`
	KDF   string    `json:"KDF"`
	MAC   string    `json:"MAC"`
	KSF   string    `json:"KSF"`
	Name  string    `json:"Name"`
	OPRF  ByteToHex `json:"OPRF"`
}

type inputs struct {
	BlindLogin            ByteToHex `json:"blind_login"`
	BlindRegistration     ByteToHex `json:"blind_registration"`
	ClientIdentity        ByteToHex `json:"client_identity,omitempty"`
	Context               ByteToHex `json:"context"`
	ClientKeyshare        ByteToHex `json:"client_keyshare"`
	ClientNonce           ByteToHex `json:"client_nonce"`
	ClientPrivateKeyshare ByteToHex `json:"client_private_keyshare"`
	CredentialIdentifier  ByteToHex `json:"credential_identifier"`
	EnvelopeNonce         ByteToHex `json:"envelope_nonce"`
	MaskingNonce          ByteToHex `json:"masking_nonce"`
	OprfKey               ByteToHex `json:"oprf_key"`
	OprfSeed              ByteToHex `json:"oprf_seed"`
	Password              ByteToHex `json:"password"`
	ServerIdentity        ByteToHex `json:"server_identity,omitempty"`
	ServerKeyshare        ByteToHex `json:"server_keyshare"`
	ServerNonce           ByteToHex `json:"server_nonce"`
	ServerPrivateKey      ByteToHex `json:"server_private_key"`
	ServerPrivateKeyshare ByteToHex `json:"server_private_keyshare"`
	ServerPublicKey       ByteToHex `json:"server_public_key"`
	KE1                   ByteToHex `json:"KE1"`               // Used for fake credentials tests
	ClientPublicKey       ByteToHex `json:"client_public_key"` // Used for fake credentials tests
	MaskingKey            ByteToHex `json:"masking_key"`       // Used for fake credentials tests
}

type intermediates struct {
	AuthKey         ByteToHex `json:"auth_key"`       //
	ClientMacKey    ByteToHex `json:"client_mac_key"` //
	ClientPublicKey ByteToHex `json:"client_public_key"`
	Envelope        ByteToHex `json:"envelope"`         //
	HandshakeSecret ByteToHex `json:"handshake_secret"` //
	MaskingKey      ByteToHex `json:"masking_key"`
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

func (v *vector) testRegistration(p *opaque.Configuration, t *testing.T) {
	// Client
	client, _ := p.Client()
	client.OPRF = buildOPRFClient(oprf.Ciphersuite(p.OPRF), v.Inputs.BlindRegistration)
	regReq := client.RegistrationInit(v.Inputs.Password)

	if !bytes.Equal(v.Outputs.RegistrationRequest, regReq.Serialize()) {
		t.Fatalf("registration requests do not match\nwant: %v\ngot : %v", hex.EncodeToString(v.Outputs.RegistrationRequest), hex.EncodeToString(regReq.Serialize()))
	}

	// Server
	server, _ := p.Server()
	pks, err := server.Group.NewElement().Decode(v.Inputs.ServerPublicKey)
	if err != nil {
		panic(err)
	}

	if pks.IsIdentity() {
		panic("identity")
	}

	regResp := server.RegistrationResponse(regReq, pks, v.Inputs.CredentialIdentifier, v.Inputs.OprfSeed)

	vRegResp, err := client.DeserializeRegistrationResponse(v.Outputs.RegistrationResponse)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(vRegResp.EvaluatedMessage.Bytes(), regResp.EvaluatedMessage.Bytes()) {
		t.Logf("%v\n%v", vRegResp.EvaluatedMessage.Bytes(), regResp.EvaluatedMessage.Bytes())
		t.Fatal("registration response data do not match")
	}

	if !bytes.Equal(vRegResp.Pks.Bytes(), regResp.Pks.Bytes()) {
		t.Fatal("registration response serverPublicKey do not match")
	}

	if !bytes.Equal(v.Outputs.RegistrationResponse, regResp.Serialize()) {
		t.Fatal("registration responses do not match")
	}

	// Client
	clientCredentials := &opaque.Credentials{
		Client:       v.Inputs.ClientIdentity,
		Server:       v.Inputs.ServerIdentity,
		TestEnvNonce: v.Inputs.EnvelopeNonce,
	}

	upload, exportKey := client.RegistrationFinalize(clientCredentials, regResp)

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

func (v *vector) testLogin(p *opaque.Configuration, t *testing.T) {
	// Client
	client, _ := p.Client()

	if !isFake(v.Config.Fake) {
		client.OPRF = buildOPRFClient(oprf.Ciphersuite(p.AKE), v.Inputs.BlindLogin)
		esk, err := client.Group.NewScalar().Decode(v.Inputs.ClientPrivateKeyshare)
		if err != nil {
			t.Fatal(err)
		}

		client.Ake.SetValues(client.Parameters.Group, esk, v.Inputs.ClientNonce, 32)
		KE1 := client.LoginInit(v.Inputs.Password)

		if !bytes.Equal(v.Outputs.KE1, KE1.Serialize()) {
			t.Fatalf("KE1 do not match")
		}
	}

	// Server
	server, _ := p.Server()

	record := &opaque.ClientRecord{}
	if !isFake(v.Config.Fake) {
		cupload, err := server.DeserializeRegistrationRecord(v.Outputs.RegistrationRecord)
		if err != nil {
			t.Fatal(err)
		}

		record.RegistrationRecord = cupload
	} else {
		rec, err := server.DeserializeRecord(encoding.Concat3(v.Inputs.ClientPublicKey, v.Inputs.MaskingKey, opaque.GetFakeEnvelope(p)))
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
	cke2, err := client.DeserializeKE2(v.Outputs.KE2)
	if err != nil {
		t.Fatal(err)
	}

	ke3, exportKey, err := client.LoginFinish(v.Inputs.ClientIdentity, v.Inputs.ServerIdentity, cke2)
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

func (v *vector) test(t *testing.T) {
	//mode, err := hex.DecodeString(v.Config.EnvelopeMode)
	//if err != nil {
	//	t.Fatal(err)
	//}

	p := &opaque.Configuration{
		OPRF:    opaque.Group(v.Config.OPRF[1]),
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

	// Login
	v.testLogin(p, t)
}

func (v *vector) loginResponse(t *testing.T, s *opaque.Server, record *opaque.ClientRecord) {
	sks, err := s.Parameters.Group.NewScalar().Decode(v.Inputs.ServerPrivateKeyshare)
	if err != nil {
		t.Fatal(err)
	}
	s.Ake.SetValues(s.Parameters.Group, sks, v.Inputs.ServerNonce, 32)

	var ke1 *message.KE1
	if isFake(v.Config.Fake) {
		ke1, err = s.DeserializeKE1(v.Inputs.KE1)
	} else {
		ke1, err = s.DeserializeKE1(v.Outputs.KE1)
	}

	if err != nil {
		t.Fatal(err)
	}

	ke2, err := s.LoginInit(ke1, v.Inputs.ServerIdentity, v.Inputs.ServerPrivateKey, v.Inputs.ServerPublicKey, v.Inputs.OprfSeed, record)
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
		vectorKE3, err := s.DeserializeKE3(v.Outputs.KE3)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(vectorKE3.Mac, s.ExpectedMAC()) {
			t.Fatalf("Expected client MACs do not match : %v", s.ExpectedMAC())
		}

		if !bytes.Equal(v.Outputs.SessionKey, s.SessionKey()) {
			t.Fatalf("Server's session key is invalid : %v", v.Outputs.SessionKey)
		}
	}

	vectorKE2, err := s.DeserializeKE2(v.Outputs.KE2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(vectorKE2.CredentialResponse.EvaluatedMessage.Bytes(), ke2.CredentialResponse.EvaluatedMessage.Bytes()) {
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

	if !bytes.Equal(vectorKE2.NonceS, ke2.NonceS) {
		t.Fatal("nonces do not match")
	}

	if !bytes.Equal(vectorKE2.EpkS.Bytes(), ke2.EpkS.Bytes()) {
		t.Fatal("epks do not match")
	}

	if !bytes.Equal(vectorKE2.Mac, ke2.Mac) {
		t.Fatalf("server macs do not match")
	}

	if !bytes.Equal(v.Outputs.KE2, ke2.Serialize()) {
		t.Fatalf("KE2 do not match")
	}

	if !isFake(v.Config.Fake) && !bytes.Equal(v.Outputs.SessionKey, s.Ake.SessionKey()) {
		t.Fatalf("Server SessionKey do not match:\n%v\n%v", v.Outputs.SessionKey, s.Ake.SessionKey())
	}
}

func buildOPRFClient(cs oprf.Ciphersuite, blind []byte) *oprf.Client {
	b, err := cs.Group().NewScalar().Decode(blind)
	if err != nil {
		panic(err)
	}

	c := cs.Client()
	c.SetBlind(b)

	return c
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
		panic("group not recognised")
	}
}

type draftVectors []*vector

func TestOpaqueVectors(t *testing.T) {
	if err := filepath.Walk("vectors.json",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var v draftVectors
			errJSON := json.Unmarshal(contents, &v)
			if errJSON != nil {
				return errJSON
			}

			for _, tv := range v {
				t.Run(fmt.Sprintf("%s - %s - Fake:%s", tv.Config.Name, tv.Config.Group, tv.Config.Fake), tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}
