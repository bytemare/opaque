// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package tests

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

		expected := "input server public key's length is invalid"
		if err := server.SetKeyMaterial(nil, sk, nil, oprfSeed); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil pubkey - got %s", err)
		}

		expected = "invalid server public key: "
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
		expected := opaque.ErrInvalidOPRFSeedLength

		if err := server.SetKeyMaterial(nil, sk, pk, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on nil seed - got %s", err)
		}

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

func TestServerInit_NilSecretKey(t *testing.T) {
	/*
		Nil server secret key
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		_, pk := conf.conf.KeyGen()
		expected := "invalid server AKE secret key: "

		if err := server.SetKeyMaterial(nil, nil, pk, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	})
}

func TestServerInit_ZeroSecretKey(t *testing.T) {
	/*
		Nil server secret key
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		sk := [32]byte{}
		expected := "server private key is zero"

		if err := server.SetKeyMaterial(nil, sk[:], nil, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	})
}

func TestServerInit_NoKeyMaterial(t *testing.T) {
	/*
		SetKeyMaterial has not been called or was not successful
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		expected := "key material not set: call SetKeyMaterial() to set values"

		if _, err := server.LoginInit(nil, nil); err == nil ||
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
		rec := buildRecord(internal.RandomBytes(32), oprfSeed, []byte("yo"), pk, client, server)
		rec.Envelope = internal.RandomBytes(15)

		expected := "record has invalid envelope length"
		if _, err := server.LoginInit(nil, rec); err == nil ||
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
		ke1 := client.LoginInit([]byte("yo")).Serialize()
		badke1 := encoding.Concat(
			ke1[:server.GetConf().OPRF.Group().ElementLength()+server.GetConf().NonceLen],
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
	rec := buildRecord(credId, oprfSeed, password, pk, client, server)
	ke1 := client.LoginInit(password)
	ke2, err := server.LoginInit(ke1, rec)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, err := client.LoginFinish(ke2)
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
	password := []byte("yo")
	credId := internal.RandomBytes(32)
	seed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ = conf.Server()
	sk, pk := conf.KeyGen()
	rec := buildRecord(credId, seed, password, pk, client, server)
	ke1 := client.LoginInit(password)
	_ = server.SetKeyMaterial(nil, sk, pk, seed)
	_, _ = server.LoginInit(ke1, rec)
	state := server.SerializeState()
	if err := server.SetAKEState(state); err == nil || err.Error() != errStateExists.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errStateExists, err)
	}
}
