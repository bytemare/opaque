// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"encoding/hex"
	"log"
	"strings"
	"testing"

	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
)

/*
	The following tests look for failing conditions.
*/

func TestClientRegistrationFinalize_InvalidPks(t *testing.T) {
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

		_, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())
		r1 := client.RegistrationInit([]byte("yo"))

		pk := server.GetConf().Group.NewElement()
		if err := pk.Decode(pks); err != nil {
			panic(err)
		}
		r2 := server.RegistrationResponse(r1, pk, credID, oprfSeed)

		// message length
		badr2 := internal.RandomBytes(15)
		expected := "invalid message length"
		if _, err := client.Deserialize.RegistrationResponse(badr2); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for empty server public key - got %v", err)
		}

		// invalid data
		badr2 = encoding.Concat(getBadElement(t, conf), pks)
		expected = "invalid OPRF evaluation"
		if _, err := client.Deserialize.RegistrationResponse(badr2); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for empty server public key - got %v", err)
		}

		// nil pks
		expected = "invalid server public key"
		badr2 = encoding.Concat(r2.Serialize()[:client.GetConf().OPRF.Group().ElementLength()], getBadElement(t, conf))
		if _, err := client.Deserialize.RegistrationResponse(badr2); err == nil ||
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

		_ = client.GenerateKE1([]byte("yo"))
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
		if _, err := client.Deserialize.KE2(badKe2); err == nil || !strings.HasPrefix(err.Error(), expected) {
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

		if err := server.SetKeyMaterial(nil, sks, pks, oprfSeed); err != nil {
			t.Fatal(err)
		}

		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.GenerateKE1([]byte("yo"))
		ke2, _ := server.GenerateKE2(ke1, rec)

		goodLength := client.GetConf().Group.ElementLength() + client.GetConf().EnvelopeSize
		expected := "invalid masked response length"

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for short response - got %v", err)
		}

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
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

		if err := server.SetKeyMaterial(nil, sks, pks, oprfSeed); err != nil {
			t.Fatal(err)
		}

		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.GenerateKE1([]byte("yo"))
		ke2, _ := server.GenerateKE2(ke1, rec)

		env, _, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(client.GetConf().MAC.Size())
		clear := encoding.Concat(pks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clear)

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

		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.GenerateKE1([]byte("yo"))
		ke2, _ := server.GenerateKE2(ke1, rec)
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
			rec.RegistrationRecord.PublicKey.Encode(),
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

		clear := encoding.Concat(badpks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = "unmasking: invalid server public key in masked response"
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error %q for invalid envelope mac - got %q", expected, err)
		}

		// replace PKS
		group := server.GetConf().Group
		fakepks := group.Base().Multiply(group.NewScalar().Random()).Encode()
		clear = encoding.Concat(fakepks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clear)

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

		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.GenerateKE1([]byte("yo"))
		ke2, _ := server.GenerateKE2(ke1, rec)

		ke2.ServerMac = internal.RandomBytes(client.GetConf().MAC.Size())
		expected := "finalizing AKE: invalid server mac"
		if _, _, err := client.GenerateKE3(ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error %q for invalid epks encoding - got %q", expected, err)
		}
	})
}

func TestClientFinish_MissingKe1(t *testing.T) {
	expectedError := "missing KE1 in client state"
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

func TestClientKSF(t *testing.T) {
	tests := []struct {
		name   string
		Input  string
		Output string
		KSF    opaque.KSFConfiguration
	}{
		{
			name: "Argon2id",
			KSF: opaque.KSFConfiguration{
				Identifier: ksf.Argon2id,
				Salt:       []byte("salt"),
				Parameters: []int{3, 65536, 4},
			},
			Input:  "password",
			Output: "ca51a24bb2c50588ab0614dc957140a2d37cea4337cc356412aa5e7035fe9508",
		},
		{
			name: "Scrypt",
			KSF: opaque.KSFConfiguration{
				Identifier: ksf.Scrypt,
				Salt:       []byte("salt"),
				Parameters: []int{32768, 8, 1},
			},
			Input:  "password",
			Output: "4bc0fd507e93a600768021341ec726c57c00cb55a4702a1650131365500cf471",
		},
		{
			name: "PBKDF2",
			KSF: opaque.KSFConfiguration{
				Identifier: ksf.PBKDF2Sha512,
				Salt:       []byte("salt"),
				Parameters: []int{10000},
			},
			Input:  "password",
			Output: "72629a41b076e588fba8c71ca37fadc9acdc8e7321b9cb4ea55fd0bf9fe8ed72",
		},
		{
			name: "Identity",
			KSF: opaque.KSFConfiguration{
				Identifier: 0,
				Salt:       []byte("salt"),
				Parameters: []int{1, 2},
			},
			Input:  "password",
			Output: "70617373776f7264",
		},
	}

	for _, ksfTest := range tests {
		t.Run(ksfTest.name, func(t *testing.T) {
			f := internal.NewKSF(ksfTest.KSF.Identifier)
			f.Parameterize(ksfTest.KSF.Parameters...)

			if ksfTest.Output != hex.EncodeToString(f.Harden([]byte(ksfTest.Input), ksfTest.KSF.Salt, 32)) {
				t.Fatal("unexpected KSF output")
			}
		})
	}
}
