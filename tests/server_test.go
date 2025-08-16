// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

/*
	The following tests look for failing conditions.
*/

func TestServer_BadRegistrationRequest(t *testing.T) {
	/*
		Error in OPRF
		- client blinded element invalid point encoding
	*/

	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			_, err = server.Deserialize.RegistrationRequest(nil)
			return err
		}, errInvalidMessageLength)

		bad := conf.getBadElement()

		expectErrors(t, func() error {
			_, err = server.Deserialize.RegistrationRequest(bad)
			return err
		}, opaque.ErrRegistrationRequest)
	})
}

func TestServerInit_InvalidOPRFSeedLength(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		sk, pk := conf.conf.KeyGen()

		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: pk.Encode(),
			OPRFGlobalSeed: nil,
		}

		if err = server.SetKeyMaterial(skm); err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		fakeRecord, err := conf.conf.GetFakeRecord(credentialIdentifier)
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		seeds := []struct {
			expected error
			name     string
			seed     []byte
		}{
			{
				name:     "nil seed",
				seed:     nil,
				expected: internal.ErrOPRFKeyNoSeed,
			},
			{
				name:     "short seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() - 1),
				expected: internal.ErrInvalidOPRFSeedLength,
			},
			{
				name:     "long seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() + 1),
				expected: internal.ErrInvalidOPRFSeedLength,
			},
		}

		for _, tt := range seeds {
			t.Run(tt.name, func(t2 *testing.T) {
				server.ServerKeyMaterial.OPRFGlobalSeed = tt.seed

				expectErrors(t, func() error {
					_, err = server.RegistrationResponse(nil, credentialIdentifier, nil)
					return err
				}, tt.expected)

				ke1, err := client.GenerateKE1(password)
				if err != nil {
					t.Fatalf("unexpected error %s", err)
				}

				client.ClearState()

				expectErrors(t, func() error {
					_, _, err := server.GenerateKE2(ke1, fakeRecord)
					return err
				}, tt.expected)
			})
		}
	})
}

//func TestServerInit_NilSecretKey(t *testing.T) {
//	/*
//		Nil server secret key
//	*/
//	testAll(t, func(t2 *testing.T, conf *configuration) {
//		server, err := conf.conf.Server()
//		if err != nil {
//			t.Fatal(err)
//		}
//		_, pk := conf.conf.KeyGen()
//		expected := "invalid server AKE secret key: "
//
//		if err := server.SetKeyMaterial(nil, nil, pk, nil); err == nil ||
//			!strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("expected error on nil secret key - got %s", err)
//		}
//	})
//}

//func TestServerInit_ZeroSecretKey(t *testing.T) {
//	/*
//		Nil server secret key
//	*/
//	testAll(t, func(t2 *testing.T, conf *configuration) {
//		server, err := conf.conf.Server()
//		if err != nil {
//			t.Fatal(err)
//		}
//		sk := [32]byte{}
//
//		var expected string
//
//		switch conf.conf.AKE.Group() {
//		case group.Ristretto255Sha512, group.P256Sha256:
//			expected = "server private key is zero"
//		default:
//			expected = "invalid server AKE secret key: scalar Decode: invalid scalar length"
//		}
//
//		if err := server.SetKeyMaterial(nil, sk[:], nil, nil); err == nil ||
//			!strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("expected error on nil secret key - got %s", err)
//		}
//	})
//}

func TestServerInit_NoKeyMaterial(t *testing.T) {
	/*
		SetKeyMaterial has not been called or was not successful
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			err = server.SetKeyMaterial(nil)
			return err
		}, internal.ErrServerKeyMaterialNil)

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			_, _, err = server.GenerateKE2(ke1, nil)
			return err
		}, internal.ErrServerKeyMaterialNil)
	})
}

func TestServerInit_InvalidEnvelope(t *testing.T) {
	/*
		Record envelope of invalid length
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		sk, pks := conf.conf.KeyGen()
		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: pks.Encode(),
			OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(t, conf, internal.RandomBytes(32), password)
		if err != nil {
			t.Fatal(err)
		}

		rec.Envelope = internal.RandomBytes(15)

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			_, _, err = server.GenerateKE2(ke1, rec)
			return err
		}, opaque.ErrClientRecord, internal.ErrEnvelopeInvalid, internal.ErrInvalidEncodingLength)
	})
}

func TestServerFinish_InvalidKE3Mac(t *testing.T) {
	/*
		ke3 mac is invalid
	*/
	conf := configurationTable[0]
	client, server := setup(t, conf)

	record := registration(t, client, server, password, credentialIdentifier, nil, nil)
	client.ClearState()

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	ke2, serverOutput, err := server.GenerateKE2(ke1, record)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, _, err := client.GenerateKE3(ke2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ke3.ClientMac[0] = ^ke3.ClientMac[0]

	expectErrors(t, func() error {
		err = server.LoginFinish(ke3, serverOutput.ClientMAC)
		return err
	}, opaque.ErrAuthentication, internal.ErrClientAuthentication)
}
