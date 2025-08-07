// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
)

var (
	errInvalidStateLength = errors.New("invalid state length")
	errStateExists        = errors.New("setting AKE state: existing state is not empty")
)

/*
	The following tests look for failing conditions.
*/

func TestServer_BadRegistrationRequest(t *testing.T) {
	/*
		Error in OPRF
		- client blinded element invalid point encoding
	*/
	err1 := "invalid message length"
	err2 := "blinded data is an invalid point"

	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.Deserialize.RegistrationRequest(nil); err == nil || !strings.HasPrefix(err.Error(), err1) {
			t.Fatalf("expected error. Got %v", err)
		}

		bad := getBadElement(t, conf)
		if _, err := server.Deserialize.RegistrationRequest(bad); err == nil || !strings.HasPrefix(err.Error(), err2) {
			t.Fatalf("expected error. Got %v", err)
		}
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
			OPRFGlobalSeed: nil,
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		fakeRecord, err := conf.conf.GetFakeRecord([]byte("credid"))
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		seeds := []struct {
			expected error
			name     string
			seed     []byte
		}{
			{
				name:     "nil seed",
				seed:     nil,
				expected: opaque.ErrServerKeyMaterialNoOPRFSeed,
			},
			{
				name:     "short seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() - 1),
				expected: opaque.ErrServerKeyMaterialInvalidOPRFSeedLength,
			},
			{
				name:     "long seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() + 1),
				expected: opaque.ErrServerKeyMaterialInvalidOPRFSeedLength,
			},
		}

		for _, tt := range seeds {
			t.Run(tt.name, func(t2 *testing.T) {
				server.ServerKeyMaterial.OPRFGlobalSeed = tt.seed

				if _, err := server.RegistrationResponse(nil, pk.Encode(), []byte("credid")); err == nil ||
					!errors.Is(err, tt.expected) {
					t.Fatalf("expected error on bad seed length - want %q, got %q", tt.expected, err)
				}

				if _, _, err := server.GenerateKE2(nil, fakeRecord); err == nil || !errors.Is(err, tt.expected) {
					t.Fatalf("expected error on bad seed length - want %q, got %q", tt.expected, err)
				}
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
		expected := opaque.ErrServerKeyMaterialNil

		if err := server.SetKeyMaterial(nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on nil key material - got %q", err)
		}

		expected = opaque.ErrServerKeyMaterialNil
		if _, _, err := server.GenerateKE2(nil, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error not calling SetKeyMaterial - want %q, got %q", expected, err)
		}
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
		sk, pk := conf.conf.KeyGen()
		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(conf.conf, skm, pk.Encode(), internal.RandomBytes(32), []byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		rec.Envelope = internal.RandomBytes(15)

		expected := "invalid client record: invalid envelope length"
		if _, _, err := server.GenerateKE2(nil, rec); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	})
}

func TestServerInit_InvalidData(t *testing.T) {
	/*
		Invalid OPRF data in KE1
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		ke1 := encoding.Concatenate(
			getBadElement(t, conf),
			internal.RandomBytes(conf.internal.NonceLen),
			internal.RandomBytes(conf.internal.Group.ElementLength()),
		)
		expected := "blinded data is an invalid point"
		if _, err := server.Deserialize.KE1(ke1); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad oprf request - got %s", err)
		}
	})
}

func TestServerInit_InvalidEPKU(t *testing.T) {
	/*
		Invalid EPKU in KE1
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}
		ke1, err := client.GenerateKE1([]byte("yo"))
		if err != nil {
			t.Fatal(err)
		}

		ke1m := ke1.Serialize()
		badke1 := encoding.Concat(
			ke1m[:conf.internal.OPRF.Group().ElementLength()+conf.internal.NonceLen],
			getBadElement(t, conf),
		)
		expected := "invalid ephemeral client public key"
		if _, err := server.Deserialize.KE1(badke1); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad epku - got %s", err)
		}
	})
}

func TestServerFinish_InvalidKE3Mac(t *testing.T) {
	/*
		ke3 mac is invalid
	*/
	password := []byte("yo")
	conf := opaque.DefaultConfiguration()
	credId := internal.RandomBytes(32)
	client, _ := conf.Client()
	server, _ := conf.Server()

	sk, pk := conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil,
		PrivateKey:     sk,
		OPRFGlobalSeed: internal.RandomBytes(conf.Hash.Size()),
	}

	if err := server.SetKeyMaterial(skm); err != nil {
		t.Fatal(err)
	}

	rec, err := buildRecord(conf, skm, pk.Encode(), credId, password)
	if err != nil {
		t.Fatal(err)
	}

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	ke2, serverOutput, err := server.GenerateKE2(ke1, rec)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, _, err := client.GenerateKE3(ke2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ke3.ClientMac[0] = ^ke3.ClientMac[0]

	expected := opaque.ErrAkeInvalidClientMac
	if err := server.LoginFinish(ke3, serverOutput.ClientMAC); err == nil || err.Error() != expected.Error() {
		t.Fatalf("expected error on invalid mac - got %v", err)
	}
}
