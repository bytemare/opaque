// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
)

const dbgErr = "%v"

type testParams struct {
	*opaque.Configuration
	serverSecretKey                                                  *ecc.Scalar
	serverPublicKey                                                  *ecc.Element
	username, userID, serverID, password, oprfSeed, ksfSalt, kdfSalt []byte
	ksfParameters                                                    []int
	ksfLength, nonceLength                                           int
}

func TestFull(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")
	password := []byte("password")

	conf := opaque.DefaultConfiguration()
	conf.Context = []byte("OPAQUETest")
	conf.KSF = ksf.Argon2id

	tester := &testParams{
		Configuration: conf,
		username:      username,
		userID:        username,
		serverID:      ids,
		password:      password,
		oprfSeed:      conf.GenerateOPRFSeed(),
		ksfParameters: []int{3, 65536, 4},
		ksfSalt:       []byte("ksfSalt"),
		kdfSalt:       []byte("kdfSalt"),
		nonceLength:   internal.NonceLength,
	}

	tester.serverSecretKey, tester.serverPublicKey = conf.KeyGen()

	/*
		Registration
	*/
	_, _, record, exportKeyReg := testRegistration(t, tester)

	/*
		Login
	*/
	_, _, exportKeyLogin := testAuthentication(t, tester, record)

	// Check values
	if !bytes.Equal(exportKeyReg, exportKeyLogin) {
		t.Errorf("export keys differ")
	}
}

func testRegistration(t *testing.T, p *testParams) (*opaque.Client, *opaque.Server, *opaque.ClientRecord, []byte) {
	// Client
	client, _ := p.Client()

	var m1s []byte
	{
		reqReg, err := client.RegistrationInit(p.password)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m1s = reqReg.Serialize()
	}

	// Server
	var m2s []byte
	{
		server, _ := p.Server()
		server.ServerKeyMaterial = &opaque.ServerKeyMaterial{
			PublicKeyBytes: p.serverPublicKey.Encode(),
			OPRFGlobalSeed: p.oprfSeed,
		}

		m1, err := server.Deserialize.RegistrationRequest(m1s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		respReg, err := server.RegistrationResponse(m1, credentialIdentifier, nil)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m2s = respReg.Serialize()
	}

	// Client
	var m3s []byte
	var exportKeyReg []byte
	{
		m2, err := client.Deserialize.RegistrationResponse(m2s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		upload, key, err := client.RegistrationFinalize(m2, p.username, p.serverID, &opaque.ClientOptions{
			KDFSalt:       p.kdfSalt,
			KSFSalt:       p.ksfSalt,
			KSFParameters: p.ksfParameters,
			KSFLength:     p.ksfLength,
		})
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		exportKeyReg = key

		m3s = upload.Serialize()
	}

	// Server
	{
		server, _ := p.Server()
		m3, err := server.Deserialize.RegistrationRecord(m3s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		return client, server, &opaque.ClientRecord{
			CredentialIdentifier: credentialIdentifier,
			ClientIdentity:       p.username,
			RegistrationRecord:   m3,
		}, exportKeyReg
	}
}

func testAuthentication(
	t *testing.T,
	p *testParams,
	record *opaque.ClientRecord,
) (*opaque.Client, *opaque.Server, []byte) {
	// Client
	client, err := p.Client()
	if err != nil {
		t.Fatalf(dbgErr, err)
	}

	var m4s []byte
	{
		ke1, err := client.GenerateKE1(p.password)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m4s = ke1.Serialize()
	}

	// Server
	var m5s []byte
	server, _ := p.Server()
	var serverOutput *opaque.ServerOutput
	{
		skm := &opaque.ServerKeyMaterial{
			Identity:       p.serverID,
			PrivateKey:     p.serverSecretKey,
			PublicKeyBytes: p.serverPublicKey.Encode(),
			OPRFGlobalSeed: p.oprfSeed,
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatalf(dbgErr, err)
		}

		m4, err := server.Deserialize.KE1(m4s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		var ke2 *message.KE2
		ke2, serverOutput, err = server.GenerateKE2(m4, record)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m5s = ke2.Serialize()
	}

	// Client
	var m6s []byte
	var exportKeyLogin []byte
	var clientKey []byte
	{
		m5, err := client.Deserialize.KE2(m5s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		var ke3 *message.KE3
		ke3, clientKey, exportKeyLogin, err = client.GenerateKE3(m5, p.username, p.serverID, &opaque.ClientOptions{
			KDFSalt:       p.kdfSalt,
			KSFSalt:       p.ksfSalt,
			KSFParameters: p.ksfParameters,
			KSFLength:     p.ksfLength,
		})
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m6s = ke3.Serialize()
	}

	// Server
	{
		m6, err := server.Deserialize.KE3(m6s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		if err := server.LoginFinish(m6, serverOutput.ClientMAC); err != nil {
			t.Fatalf(dbgErr, err)
		}
	}

	if !bytes.Equal(clientKey, serverOutput.SessionSecret) {
		t.Log(hex.EncodeToString(clientKey))
		t.Log(hex.EncodeToString(serverOutput.SessionSecret))
		t.Fatalf("session keys differ")
	}

	return client, server, exportKeyLogin
}

func isSameConf(a, b *opaque.Configuration) bool {
	if a.OPRF != b.OPRF {
		return false
	}
	if a.KDF != b.KDF {
		return false
	}
	if a.MAC != b.MAC {
		return false
	}
	if a.Hash != b.Hash {
		return false
	}
	if !reflect.DeepEqual(a.KSF, b.KSF) {
		return false
	}
	if a.AKE != b.AKE {
		return false
	}

	return bytes.Equal(a.Context, b.Context)
}

func TestConfiguration_Deserialization(t *testing.T) {
	conf := opaque.DefaultConfiguration()
	ser := conf.Serialize()

	conf2, err := opaque.DeserializeConfiguration(ser)
	if err != nil {
		t.Fatalf("unexpected error on valid configuration: %v", err)
	}

	if !isSameConf(conf, conf2) {
		t.Fatalf("Unexpected inequality:\n\t%v\n\t%v", conf, conf2)
	}
}

func TestFlush(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")

	conf := opaque.DefaultConfiguration()
	conf.Context = []byte("OPAQUETest")

	test := &testParams{
		Configuration: conf,
		username:      username,
		userID:        username,
		serverID:      ids,
		password:      password,
		oprfSeed:      conf.GenerateOPRFSeed(),
	}

	test.serverSecretKey, test.serverPublicKey = conf.KeyGen()

	/*
		Registration
	*/
	_, _, record, _ := testRegistration(t, test)

	/*
		Login
	*/
	client, _, _ := testAuthentication(t, test, record)

	client.ClearState()
}

/*
	The following tests look for failing conditions.
*/

func TestDeserializeConfiguration_InvalidContextHeader(t *testing.T) {
	d := opaque.DefaultConfiguration().Serialize()
	d[7] = 20

	expectErrors(t, func() error {
		_, err := opaque.DeserializeConfiguration(d)
		return err
	}, opaque.ErrConfiguration, internal.ErrInvalidContextEncoding, encoding.ErrTotalLength)
}

func TestDeserializeConfiguration_Short(t *testing.T) {
	r7 := internal.RandomBytes(7)

	expectErrors(t, func() error {
		_, err := opaque.DeserializeConfiguration(r7)
		return err
	}, opaque.ErrConfiguration, internal.ErrInvalidEncodingLength)
}

func TestBadConfiguration(t *testing.T) {
	setBadValue := func(pos, val int) []byte {
		b := opaque.DefaultConfiguration().Serialize()
		b[pos] = byte(val)
		return b
	}

	tests := []struct {
		error   error
		makeBad func() []byte
		name    string
	}{
		{
			name: "Bad OPRF",
			makeBad: func() []byte {
				return setBadValue(0, 0)
			},
			error: internal.ErrInvalidOPRFid,
		},
		{
			name: "Bad AKE",
			makeBad: func() []byte {
				return setBadValue(1, 0)
			},
			error: internal.ErrInvalidAKEid,
		},
		{
			name: "Bad KSF",
			makeBad: func() []byte {
				return setBadValue(2, 10)
			},
			error: internal.ErrInvalidKSFid,
		},
		{
			name: "Bad KDF",
			makeBad: func() []byte {
				return setBadValue(3, 0)
			},
			error: internal.ErrInvalidKDFid,
		},
		{
			name: "Bad MAC",
			makeBad: func() []byte {
				return setBadValue(4, 0)
			},
			error: internal.ErrInvalidMACid,
		},
		{
			name: "Bad Hash",
			makeBad: func() []byte {
				return setBadValue(5, 0)
			},
			error: internal.ErrInvalidHASHid,
		},
	}

	convertToBadConf := func(encoded []byte) *opaque.Configuration {
		return &opaque.Configuration{
			OPRF:    opaque.Group(encoded[0]),
			AKE:     opaque.Group(encoded[1]),
			KSF:     ksf.Identifier(encoded[2]),
			KDF:     crypto.Hash(encoded[3]),
			MAC:     crypto.Hash(encoded[4]),
			Hash:    crypto.Hash(encoded[5]),
			Context: encoded[6:],
		}
	}

	for _, badConf := range tests {
		t.Run(badConf.name, func(t *testing.T) {
			// Test Deserialization for bad conf
			badEncoded := badConf.makeBad()

			expectErrors(t, func() error {
				_, err := opaque.DeserializeConfiguration(badEncoded)
				return err
			}, badConf.error)

			// Test bad configuration for client, server, and deserializer setup
			bad := convertToBadConf(badEncoded)

			expectErrors(t, func() error {
				_, err := bad.Client()
				return err
			}, badConf.error)

			expectErrors(t, func() error {
				_, err := bad.Server()
				return err
			}, badConf.error)

			expectErrors(t, func() error {
				_, err := bad.Deserializer()
				return err
			}, badConf.error)
		})
	}
}

func TestFakeRecord(t *testing.T) {
	// Test valid configurations
	testAll(t, func(t2 *testing.T, conf *configuration) {
		if _, err := conf.conf.GetFakeRecord(nil); err != nil {
			t.Fatalf("unexpected error on valid configuration: %v", err)
		}
	})

	// Test for an invalid configuration.
	conf := &opaque.Configuration{
		OPRF:    0,
		AKE:     0,
		KSF:     0,
		KDF:     0,
		MAC:     0,
		Hash:    0,
		Context: nil,
	}

	if _, err := conf.GetFakeRecord(nil); err == nil {
		t.Fatal("expected error on invalid configuration")
	}
}
