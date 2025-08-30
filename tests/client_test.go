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
	"testing"

	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	ksf2 "github.com/bytemare/opaque/internal/ksf"
	"github.com/bytemare/opaque/internal/tag"
)

// todo: identify whether we can use table tests

/*
	The following tests look for failing conditions.
*/

func TestClient_GenerateKE3_BadMaskedResponse(t *testing.T) {
	/*
		The masked response is of invalid length.
	*/

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
		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sks,
			PublicKeyBytes: pks.Encode(),
			OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(t, conf, credentialIdentifier, password)
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		goodLength := conf.internal.Group.ElementLength() + conf.internal.EnvelopeSize

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseInvalidMaskedResponse, internal.ErrInvalidEncodingLength)

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseInvalidMaskedResponse, internal.ErrInvalidEncodingLength)
	})
}

func TestClient_GenerateKE3_InvalidEnvelopeTag(t *testing.T) {
	/*
		Invalid envelope tag
	*/

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		rec := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		blind := conf.conf.OPRF.Group().NewScalar().Random()

		ke1, err := client.GenerateKE1(password, &opaque.ClientOptions{OPRFBlind: blind})
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		env, _, err := getEnvelope(conf.internal, blind, password, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(conf.internal.MAC.Size())
		clearText := encoding.Concat(server.ServerKeyMaterial.PublicKeyBytes, env.Serialize())
		ke2.MaskedResponse = xorResponse(conf.internal, rec.MaskingKey, ke2.MaskingNonce, clearText)

		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrEnvelopeInvalidMac)
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

func TestClient_GenerateKE3_ErrEnvelopeInvalidMac_WrongServerPublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t.Fatal(err)
		}

		// Use a valid encoding but with a fake public key
		group := conf.conf.AKE.Group()
		fakepks := group.Base().Multiply(group.NewScalar().Random()).Encode()
		clearText := encoding.Concat(fakepks, record.Envelope)
		ke2.MaskedResponse = xorResponse(conf.internal, record.MaskingKey, ke2.MaskingNonce, clearText)

		expectErrors(t, func() error {
			_, _, _, err := client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrEnvelopeInvalidMac)
	})
}

func TestClient_GenerateKE3_InvalidServerPublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		blind := conf.conf.OPRF.Group().NewScalar().Random()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t.Fatal(err)
		}

		env, randomizedPassword, err := getEnvelope(conf.internal, blind, password, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper server public key
		badServerPublicKey := conf.getBadElement()

		ctc := cleartextCredentials(
			record.RegistrationRecord.ClientPublicKey.Encode(),
			badServerPublicKey,
			nil,
			nil,
		)
		authKey := conf.internal.KDF.Expand(
			randomizedPassword,
			encoding.SuffixString(env.Nonce, tag.AuthKey),
			conf.internal.KDF.Size(),
		)
		authTag := conf.internal.MAC.MAC(authKey, encoding.Concat(env.Nonce, ctc))
		env.AuthTag = authTag

		// Use an invalid encoding for the server public key
		clearText := encoding.Concat(badServerPublicKey, env.Serialize())
		ke2.MaskedResponse = xorResponse(conf.internal, record.MaskingKey, ke2.MaskingNonce, clearText)

		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrAuthenticationInvalidServerPublicKey)
	})
}

func TestClient_GenerateKE3_InvalidKE2Mac(t *testing.T) {
	/*
		Invalid server ke2 mac
	*/

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t.Fatal(err)
		}

		ke2.ServerMac = internal.RandomBytes(conf.internal.MAC.Size())
		expectErrors(t, func() error {
			_, _, _, err := client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrServerAuthentication)
	})
}

/*
func TestClientFinish_MissingKe1(t *testing.T) {
	expectedError := "client state: missing KE1 message - call GenerateKE1 first"
	conf := opaque.DefaultConfiguration()
	client, err := conf.Client()
	if err != nil {
		t.Fatal(err)
	}

	server, err := conf.Server()
	if err != nil {
		t.Fatal(err)
	}

	sks, pks := conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil,
		PrivateKey:      sks,
		OPRFGlobalSeed: internal.RandomBytes(conf.Hash.Size()),
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		log.Fatal(err)
	}

	rec, err := buildRecord(pks.Encode(), []byte("id"), password, client, server)
	if err != nil {
		t.Fatal(err)
	}

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}

	ke2, _, err := server.GenerateKE2(ke1, rec)
	if err != nil {
		t.Fatal(err)
	}

	client, err = conf.Client()
	if err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := client.GenerateKE3(ke2, nil, nil); err == nil || !strings.EqualFold(err.Error(), expectedError) {
		t.Fatalf(
			"expected error when calling GenerateKE3 without pre-existing KE1, want %q, got %q",
			expectedError,
			err,
		)
	}
}

*/

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
