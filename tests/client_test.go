// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"strings"
	"testing"

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
		client, _ := conf.conf.Client()
		server, _ := conf.conf.Server()
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
		badr2 = encoding.Concat(r2.Serialize()[:client.GetConf().OPRFPointLength], getBadElement(t, conf))
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
		client, _ := conf.conf.Client()
		_ = client.LoginInit([]byte("yo"))
		r2 := encoding.Concat(
			getBadElement(t, conf),
			internal.RandomBytes(
				client.GetConf().NonceLen+client.GetConf().AkePointLength+client.GetConf().EnvelopeSize,
			),
		)
		badKe2 := encoding.Concat(
			r2,
			internal.RandomBytes(client.GetConf().NonceLen+client.GetConf().AkePointLength+client.GetConf().MAC.Size()),
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
		client, _ := conf.conf.Client()
		server, _ := conf.conf.Server()
		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)

		goodLength := encoding.PointLength[client.GetConf().Group] + client.GetConf().EnvelopeSize
		expected := "invalid masked response length"

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for short response - got %v", err)
		}

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
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
		client, _ := conf.conf.Client()
		server, _ := conf.conf.Server()
		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)

		env, _, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(client.GetConf().MAC.Size())
		clear := encoding.Concat(pks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clear)

		expected := "recover envelope: invalid envelope authentication tag"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
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
		client, _ := conf.conf.Client()
		server, _ := conf.conf.Server()
		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)
		// epks := ke2.EpkS

		// tamper epks
		offset := client.GetConf().AkePointLength + client.GetConf().MAC.Size()
		encoded := ke2.Serialize()
		badKe2 := encoding.Concat3(encoded[:len(encoded)-offset], getBadElement(t, conf), ke2.Mac)
		expected := "invalid ephemeral server public key"
		if _, err := client.Deserialize.KE2(badKe2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}

		// tamper PKS
		// ke2.EpkS = server.Group.NewElement().Mult(server.Group.NewScalar().Random())
		env, randomizedPwd, err := getEnvelope(client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		badpks := getBadElement(t, conf)

		ctc := cleartextCredentials(
			encoding.SerializePoint(rec.RegistrationRecord.PublicKey, client.GetConf().Group),
			badpks,
			nil,
			nil,
		)
		authKey := client.GetConf().KDF.Expand(
			randomizedPwd,
			encoding.SuffixString(env.Nonce, tag.AuthKey),
			client.GetConf().KDF.Size(),
		)
		authTag := client.GetConf().MAC.MAC(authKey, encoding.Concat(env.Nonce, ctc))
		env.AuthTag = authTag

		clear := encoding.Concat(badpks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = "invalid server public key"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid envelope mac - got %q", err)
		}

		// replace PKS
		group := server.GetConf().Group
		fakepks := group.Base().Multiply(group.NewScalar().Random()).Encode()
		clear = encoding.Concat(fakepks, env.Serialize())
		ke2.MaskedResponse = xorResponse(server.GetConf(), rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = "recover envelope: invalid envelope authentication tag"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid envelope mac - got %q", err)
		}
	})
}

func TestClientFinish_InvalidKE2Mac(t *testing.T) {
	/*
		Invalid server ke2 mac
	*/
	credID := internal.RandomBytes(32)

	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, _ := conf.conf.Client()
		server, _ := conf.conf.Server()
		sks, pks := conf.conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.conf.Hash.Size())
		rec := buildRecord(credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.LoginInit([]byte("yo"))
		ke2, _ := server.LoginInit(ke1, nil, sks, pks, oprfSeed, rec)

		ke2.Mac = internal.RandomBytes(client.GetConf().MAC.Size())
		expected := " AKE finalization: invalid server mac"
		if _, _, err := client.LoginFinish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}
	})
}

func TestClientFinish_MissingKe1(t *testing.T) {
	expectedError := "missing KE1 in client state"
	conf := opaque.DefaultConfiguration()
	client, _ := conf.Client()
	if _, _, err := client.LoginFinish(nil, nil, nil); err == nil || !strings.EqualFold(err.Error(), expectedError) {
		t.Fatalf(
			"expected error when calling LoginFinish without pre-existing KE1, want %q, got %q",
			expectedError,
			err,
		)
	}
}
