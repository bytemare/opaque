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
	"encoding/hex"
	"log"
	"strings"
	"testing"

	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	ksf2 "github.com/bytemare/opaque/internal/ksf"
	"github.com/bytemare/opaque/internal/tag"
)

/*
	The following tests look for failing conditions.
*/

func TestClient_Deserialize_RegistrationResponse(t *testing.T) {
	/*
		Invalid data sent to the client
	*/
	credID := internal.RandomBytes(32)

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())
		_, pks := conf.conf.KeyGen()

		if err = server.SetKeyMaterial(nil, nil, pks, oprfSeed); err != nil {
			t.Fatal(err)
		}

		// Start the registration flow.

		r1, err := client.RegistrationInit([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		r2, err := server.RegistrationResponse(r1, credID, nil)
		if err != nil {
			t.Fatal(err)
		}

		// message length
		badr2 := internal.RandomBytes(15)
		expected := "invalid message length"
		if _, err = client.Deserialize.RegistrationResponse(badr2); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for empty server public key - got %v", err)
		}

		// invalid data
		badr2 = encoding.Concat(getBadElement(t, conf), pks)
		expected = "invalid OPRF evaluation"
		if _, err = client.Deserialize.RegistrationResponse(badr2); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for empty server public key - got %v", err)
		}

		// invalid pks
		expected = "invalid server public key"
		badr2 = encoding.Concat(r2.Serialize()[:client.GetConf().OPRF.Group().ElementLength()], getBadElement(t, conf))
		if _, err = client.Deserialize.RegistrationResponse(badr2); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid server public key - got %v", err)
		}
	})
}

func TestClientFinish_BadEvaluation(t *testing.T) {
	/*
		Oprf finalize : evaluation deserialization // element decoding
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		_, err = client.GenerateKE1([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		r2 := encoding.Concat(
			getBadElement(t, conf),
			internal.RandomBytes(
				client.GetConf().NonceLen+client.GetConf().Group.ElementLength()+client.GetConf().EnvelopeSize,
			),
		)
		badKe2 := encoding.Concat(
			r2,
			internal.RandomBytes(
				client.GetConf().NonceLen+client.GetConf().Group.ElementLength()+client.GetConf().MAC.Size(),
			),
		)

		expected := "invalid OPRF evaluation"
		if _, err = client.Deserialize.KE2(badKe2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid evaluated element - got %v", err)
		}
	})
}

func TestClientFinish_BadMaskedResponse(t *testing.T) {
	/*
		The masked response is of invalid length.
	*/
	credID := internal.RandomBytes(32)

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())

		if err = server.SetKeyMaterial(nil, sks, pks, oprfSeed); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(credID, []byte("yo"), client, server)
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		ke2, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		goodLength := client.GetConf().Group.ElementLength() + client.GetConf().EnvelopeSize
		expected := "invalid masked response length"

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		if _, _, err = client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for short response - got %v", err)
		}

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		if _, _, err = client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for long response - got %v", err)
		}
	})
}

func TestClientFinish_InvalidEnvelopeTag(t *testing.T) {
	/*
		Invalid envelope tag
	*/
	credID := internal.RandomBytes(32)

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())

		if err = server.SetKeyMaterial(nil, sks, pks, oprfSeed); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(credID, []byte("yo"), client, server)
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		ke2, _ := server.GenerateKE2(ke1, rec)

		env, _, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(client.GetConf().MAC.Size())
		clearText := encoding.Concat(pks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clearText)

		expected := "key recovery: invalid envelope authentication tag"
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error = %q for invalid envelope mac - got %v", expected, err)
		}
	})
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

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())

		if err := server.SetKeyMaterial(nil, sks, pks, oprfSeed); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(credID, []byte("yo"), client, server)
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		ke2, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		// epks := ke2.ServerPublicKeyshare

		// tamper epks
		offset := client.GetConf().Group.ElementLength() + client.GetConf().MAC.Size()
		encoded := ke2.Serialize()
		badKe2 := encoding.Concat3(encoded[:len(encoded)-offset], getBadElement(t, conf), ke2.ServerMac)
		expected := "invalid ephemeral server public key"
		if _, err := client.Deserialize.KE2(badKe2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}

		// tamper PKS
		// ke2.ServerPublicKeyshare = server.Group.NewElement().Mult(server.Group.NewScalar().Random())
		env, randomizedPassword, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		badpks := getBadElement(t, conf)

		ctc := cleartextCredentials(
			rec.RegistrationRecord.ClientPublicKey.Encode(),
			badpks,
			nil,
			nil,
		)
		authKey := client.GetConf().KDF.Expand(
			randomizedPassword,
			encoding.SuffixString(env.Nonce, tag.AuthKey),
			client.GetConf().KDF.Size(),
		)
		authTag := client.GetConf().MAC.MAC(authKey, encoding.Concat(env.Nonce, ctc))
		env.AuthTag = authTag

		clearText := encoding.Concat(badpks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clearText)

		expected = "unmasking: invalid server public key in masked response"
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error %q for invalid envelope mac - got %q", expected, err)
		}

		// replace PKS
		group := server.GetConf().Group
		fakepks := group.Base().Multiply(group.NewScalar().Random()).Encode()
		clearText = encoding.Concat(fakepks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clearText)

		expected = "key recovery: invalid envelope authentication tag"
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error %q for invalid envelope mac - got %q", expected, err)
		}
	})
}

func TestClientFinish_InvalidKE2Mac(t *testing.T) {
	/*
		Invalid server ke2 mac
	*/
	credID := internal.RandomBytes(32)

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())

		if err := server.SetKeyMaterial(nil, sks, pks, oprfSeed); err != nil {
			log.Fatal(err)
		}

		rec, err := buildRecord(credID, []byte("yo"), client, server)
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		ke2, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		ke2.ServerMac = internal.RandomBytes(client.GetConf().MAC.Size())
		expected := "finalizing AKE: invalid server mac"
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error %q for invalid epks encoding - got %q", expected, err)
		}
	})
}

func TestClientFinish_MissingKe1(t *testing.T) {
	expectedError := "client state: missing KE1 message - call GenerateKE1 first"
	conf := opaque.DefaultConfiguration()
	client, _ := conf.Client()
	if _, _, err := client.GenerateKE3(nil); err == nil || !strings.EqualFold(err.Error(), expectedError) {
		t.Fatalf(
			"expected error when calling GenerateKE3 without pre-existing KE1, want %q, got %q",
			expectedError,
			err,
		)
	}
}

func TestClientPRK(t *testing.T) {
	type prkTest struct {
		name          string
		input         string
		ksfSalt       string
		kdfSalt       string
		output        string
		ksfParameters []int
		ksfLength     int
		kdf           crypto.Hash
		ksf           ksf.Identifier
	}

	tests := []prkTest{
		{
			name:          "Argon2id",
			ksf:           ksf.Argon2id,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{3, 65536, 4},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "3e858a95d7fe77be3a6278dafa572f8a3a1d49a7154e3a0710d9a5a46358fd0993d958d0963cd88c0a907d105fadcb8c0702b02f8305f8f3c77204b63a93e469",
		},
		{
			name:          "Scrypt",
			ksf:           ksf.Scrypt,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{32768, 8, 1},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "a0d28223edab936f13d778636f1801c0368c2b8d990c5be3cf93d7d1f5ade9d7634a2b20b2f09ac2f1508be6741fcd2f4279ecf33d4b672991b107463016c37f",
		},
		{
			name:          "PBKDF2",
			ksf:           ksf.PBKDF2Sha512,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{10000},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "35bd30915a0564dbd160402bec5163441cc3c8c3c9ee4cf2d87f0f2e228b514cf1c18a41ce9e84b3306286cd06032b296a4a2ff487945e59fcecbab7f06b3098",
		},
		{
			name:          "Identity",
			ksf:           0,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{1, 2},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "deba3102d5ddf4b833ff43d3d2f3fb77b9514652bb6ce7b985a091478a6c8ecaedb0354d72284202c3de9f358cba8885326403b9738835ae86b6a49fec25ab38",
		},
	}

	for _, ksfTest := range tests {
		t.Run(ksfTest.name, func(t *testing.T) {
			input := []byte(ksfTest.input)
			stretcher := ksf2.NewKSF(ksfTest.ksf)
			stretcher.Parameterize(ksfTest.ksfParameters...)
			stretched := stretcher.Harden(input, []byte(ksfTest.ksfSalt), ksfTest.ksfLength)

			extract := internal.NewKDF(ksfTest.kdf)
			output := hex.EncodeToString(extract.Extract([]byte(ksfTest.kdfSalt), encoding.Concat(input, stretched)))

			if output != ksfTest.output {
				t.Errorf("got %q, want %q", output, ksfTest.output)
			}
		})
	}
}
