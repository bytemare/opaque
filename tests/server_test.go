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
	"log"
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

func TestServerInit_InvalidPublicKey(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		sk, _ := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())

		expected := "invalid server key material: server public key length is invalid"
		if err := server.SetKeyMaterial(nil, sk, nil, oprfSeed); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil pubkey - got %s", err)
		}

		expected = "invalid server key material: invalid server public key: "
		if err := server.SetKeyMaterial(nil, sk, getBadElement(t, conf), oprfSeed); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad secret key - got %s", err)
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
		expected := opaque.ErrServerKeyMaterialInvalidOPRFSeedLength

		//if err := server.SetKeyMaterial(nil, sk, pk, nil); err == nil || !errors.Is(err, expected) {
		//	t.Fatalf("expected error on nil seed - got %s", err)
		//}

		seed := internal.RandomBytes(conf.conf.Hash.Size() - 1)
		if err := server.SetKeyMaterial(nil, sk, pk, seed); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on bad seed - got %s", err)
		}

		seed = internal.RandomBytes(conf.conf.Hash.Size() + 1)
		if err := server.SetKeyMaterial(nil, sk, pk, seed); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on bad seed - got %s", err)
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
		expected := "invalid server key material: key material not set - call SetKeyMaterial() to set values"

		record, err := conf.conf.GetFakeRecord([]byte("fake_client"))
		if err != nil {
			log.Fatalln(err)
		}

		if _, err := server.GenerateKE2(nil, record); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error not calling SetKeyMaterial - got %s", err)
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
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())

		if err := server.SetKeyMaterial(nil, sk, pk, oprfSeed); err != nil {
			t.Fatal(err)
		}

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(internal.RandomBytes(32), []byte("yo"), client, server)
		if err != nil {
			t.Fatal(err)
		}

		rec.Envelope = internal.RandomBytes(15)

		expected := "invalid client record: invalid envelope length"
		if _, err := server.GenerateKE2(nil, rec); err == nil ||
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
			internal.RandomBytes(server.GetConf().NonceLen),
			internal.RandomBytes(server.GetConf().Group.ElementLength()),
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
			ke1m[:server.GetConf().OPRF.Group().ElementLength()+server.GetConf().NonceLen],
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
	oprfSeed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ := conf.Server()

	sk, pk := conf.KeyGen()
	if err := server.SetKeyMaterial(nil, sk, pk, oprfSeed); err != nil {
		t.Fatal(err)
	}

	rec, err := buildRecord(credId, password, client, server)
	if err != nil {
		t.Fatal(err)
	}

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	ke2, err := server.GenerateKE2(ke1, rec)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, err := client.GenerateKE3(ke2)
	if err != nil {
		t.Fatal(err)
	}
	ke3.ClientMac[0] = ^ke3.ClientMac[0]

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
	password := []byte("yo")
	credId := internal.RandomBytes(32)
	seed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ = conf.Server()
	sk, pk := conf.KeyGen()

	if err := server.SetKeyMaterial(nil, sk, pk, seed); err != nil {
		t.Fatal(err)
	}

	rec, err := buildRecord(credId, password, client, server)
	if err != nil {
		t.Fatal(err)
	}

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	_ = server.SetKeyMaterial(nil, sk, pk, seed)
	_, err = server.GenerateKE2(ke1, rec)
	if err != nil {
		t.Fatal(err)
	}
	state := server.SerializeState()
	if err = server.SetAKEState(state); err == nil || err.Error() != errStateExists.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errStateExists, err)
	}
}
