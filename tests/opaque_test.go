// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto"
	"errors"
	"reflect"
	"strings"
	"testing"

	group "github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/oprf"
)

const dbgErr = "%v"

type testParams struct {
	*opaque.Configuration
	username, userID, serverID, password, serverSecretKey, serverPublicKey, oprfSeed []byte
}

func TestFull(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")
	password := []byte("password")

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

	serverSecretKey, pks := conf.KeyGen()
	test.serverSecretKey = serverSecretKey
	test.serverPublicKey = pks

	/*
		Registration
	*/
	_, _, record, exportKeyReg := testRegistration(t, test)

	/*
		Login
	*/
	_, _, exportKeyLogin := testAuthentication(t, test, record)

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
		reqReg := client.RegistrationInit(p.password)
		m1s = reqReg.Serialize()
	}

	// Server
	var m2s []byte
	var credID []byte
	{
		server, _ := p.Server()
		m1, err := server.Deserialize.RegistrationRequest(m1s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		credID = internal.RandomBytes(32)
		pks, err := server.Deserialize.DecodeAkePublicKey(p.serverPublicKey)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		respReg := server.RegistrationResponse(m1, pks, credID, p.oprfSeed)

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

		upload, key := client.RegistrationFinalize(m2, opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: p.username,
			ServerIdentity: p.serverID,
		})
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
			CredentialIdentifier: credID,
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
	client, _ := p.Client()

	var m4s []byte
	{
		ke1 := client.GenerateKE1(p.password)
		m4s = ke1.Serialize()
	}

	// Server
	var m5s []byte
	var state []byte
	server, _ := p.Server()
	{
		if err := server.SetKeyMaterial(p.serverID, p.serverSecretKey, p.serverPublicKey, p.oprfSeed); err != nil {
			t.Fatal(err)
		}

		m4, err := server.Deserialize.KE1(m4s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		ke2, err := server.GenerateKE2(m4, record)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		state = server.SerializeState()

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

		ke3, key, err := client.GenerateKE3(m5, opaque.GenerateKE3Options{
			ClientIdentity: p.username,
			ServerIdentity: p.serverID,
		})
		if err != nil {
			t.Fatalf(dbgErr, err)
		}
		exportKeyLogin = key

		m6s = ke3.Serialize()
		clientKey = client.SessionKey()
	}

	// Server
	var serverKey []byte
	{
		// here we spawn a new server instance to test setting the state
		resumedServer, _ := p.Server()
		if err := resumedServer.SetAKEState(state); err != nil {
			t.Fatalf(dbgErr, err)
		}

		m6, err := resumedServer.Deserialize.KE3(m6s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		if err := resumedServer.LoginFinish(m6); err != nil {
			t.Fatalf(dbgErr, err)
		}

		serverKey = resumedServer.SessionKey()
	}

	if !bytes.Equal(clientKey, serverKey) {
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

func TestConfiguration_KSFConfigDeserialization(t *testing.T) {
	conf := opaque.DefaultConfiguration()
	conf.KSF.Parameters = []int{2, 19456, 1}
	conf.KSF.Salt = []byte("salt")
	ser := conf.Serialize()

	conf2, err := opaque.DeserializeConfiguration(ser)
	if err != nil {
		t.Fatalf("unexpected error on valid configuration: %v", err)
	}

	if !isSameConf(conf, conf2) {
		t.Fatalf("Unexpected inequality:\n\t%v\n\t%v", conf, conf2)
	}
}

func TestConfiguration_ToInternal_KSFParameterization(t *testing.T) {
	conf := opaque.DefaultConfiguration()

	// Set explicit KSF parameters
	conf.KSF.Parameters = []int{42, 99, 7}
	conf.KSF.Salt = []byte("salt")

	_, err := conf.Deserializer()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFlush(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")
	password := []byte("password")

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

	serverSecretKey, pks := conf.KeyGen()
	test.serverSecretKey = serverSecretKey
	test.serverPublicKey = pks

	/*
		Registration
	*/
	_, _, record, _ := testRegistration(t, test)

	/*
		Login
	*/
	client, server, _ := testAuthentication(t, test, record)

	client.Ake.Flush()
	if client.SessionKey() != nil {
		t.Fatalf("client flush failed, the session key is non-nil: %v", client.SessionKey())
	}

	if client.Ake.GetEphemeralSecretKey() != nil {
		t.Fatalf("client flush failed, the ephemeral session key is non-nil: %v", client.SessionKey())
	}

	if client.Ake.GetNonce() != nil {
		t.Fatalf("client flush failed, the nonce is non-nil: %v", client.SessionKey())
	}

	server.Ake.Flush()
	if server.SessionKey() != nil {
		t.Fatalf("server flush failed, the session key is non-nil: %v", client.SessionKey())
	}

	if server.Ake.GetEphemeralSecretKey() != nil {
		t.Fatalf("server flush failed, the ephemeral session key is non-nil: %v", client.SessionKey())
	}

	if server.Ake.GetNonce() != nil {
		t.Fatalf("server flush failed, the nonce is non-nil: %v", client.SessionKey())
	}

	if server.ExpectedMAC() != nil {
		t.Fatalf("server flush failed, the expected client mac is non-nil: %v", client.SessionKey())
	}
}

/*
	The following tests look for failing conditions.
*/

func TestDeserializeConfiguration_InvalidContextHeader(t *testing.T) {
	d := opaque.DefaultConfiguration().Serialize()
	d[7] = 20

	expected := "decoding the configuration context: "
	if _, err := opaque.DeserializeConfiguration(d); err == nil || !strings.HasPrefix(err.Error(), expected) {
		t.Errorf(
			"DeserializeConfiguration did not return the appropriate error for vector invalid header. want %q, got %q",
			expected,
			err,
		)
	}
}

func TestNilConfiguration(t *testing.T) {
	def := opaque.DefaultConfiguration()
	g := group.Group(def.AKE)
	defaultConfiguration := &internal.Configuration{
		KDF:      internal.NewKDF(def.KDF),
		MAC:      internal.NewMac(def.MAC),
		Hash:     internal.NewHash(def.Hash),
		KSF:      internal.NewKSF(def.KSF.Identifier),
		NonceLen: internal.NonceLength,
		Group:    g,
		OPRF:     oprf.IDFromGroup(g),
		Context:  def.Context,
	}

	s, _ := opaque.NewServer(nil)
	if reflect.DeepEqual(s.GetConf(), defaultConfiguration) {
		t.Errorf("server did not default to correct configuration")
	}

	c, _ := opaque.NewClient(nil)
	if reflect.DeepEqual(c.GetConf(), defaultConfiguration) {
		t.Errorf("client did not default to correct configuration")
	}
}

func TestDeserializeConfiguration_Short(t *testing.T) {
	r9 := internal.RandomBytes(7)

	if _, err := opaque.DeserializeConfiguration(r9); !errors.Is(err, internal.ErrConfigurationInvalidLength) {
		t.Errorf("DeserializeConfiguration did not return the appropriate error for vector r9. want %q, got %q",
			internal.ErrConfigurationInvalidLength, err)
	}
}

func TestConfiguration_Bad_KSFConfigDeserialization(t *testing.T) {
	conf := opaque.DefaultConfiguration()
	conf.KSF.Parameters = []int{2, 19456, 1}
	conf.KSF.Salt = []byte("salt")
	ser := conf.Serialize()
	// Bad header, not multiple of 4
	ser[9] = 7
	expected := "decoding the KSF configuration: invalid ksf configuration encoding header"
	if _, err := opaque.DeserializeConfiguration(ser); err == nil || err.Error() != expected {
		t.Fatalf(
			"DeserializeConfiguration did not return the appropriate error for vector invalid header. want %q, got %q",
			expected,
			err,
		)
	}
	// KSF params too short
	ser[9] = 12
	expected = "decoding the KSF configuration: decoding the ksf configuration parameters: insufficient total length for decoding"
	if _, err := opaque.DeserializeConfiguration(ser[:12+(len(conf.KSF.Parameters)-1)*4]); err == nil ||
		err.Error() != expected {
		t.Fatalf(
			"DeserializeConfiguration did not return the appropriate error for vector invalid header. want %q, got %q",
			expected,
			err,
		)
	}
	// Bad Salt header: too short
	expected = "decoding the KSF configuration: decoding the ksf salt: insufficient header length for decoding"
	if _, err := opaque.DeserializeConfiguration(ser[:len(ser)-len(conf.KSF.Salt)-1]); err == nil ||
		err.Error() != expected {
		t.Fatalf(
			"DeserializeConfiguration did not return the appropriate error for vector invalid header. want %q, got %q",
			expected,
			err,
		)
	}
	// Bad Salt: too short
	expected = "decoding the KSF configuration: decoding the ksf salt: insufficient total length for decoding"
	if _, err := opaque.DeserializeConfiguration(ser[:len(ser)-1]); err == nil || err.Error() != expected {
		t.Fatalf("expected error on invalid configuration: %v", err)
	}
}

func TestBadConfiguration(t *testing.T) {
	setBadValue := func(pos, val int) []byte {
		b := opaque.DefaultConfiguration().Serialize()
		b[pos] = byte(val)
		return b
	}

	tests := []struct {
		name    string
		makeBad func() []byte
		error   string
	}{
		{
			name: "Bad KSF",
			makeBad: func() []byte {
				return setBadValue(0, 10)
			},
			error: "invalid KSF id",
		},
		{
			name: "Bad KDF",
			makeBad: func() []byte {
				return setBadValue(1, 0)
			},
			error: "invalid KDF id",
		},
		{
			name: "Bad MAC",
			makeBad: func() []byte {
				return setBadValue(2, 0)
			},
			error: "invalid MAC id",
		},
		{
			name: "Bad Hash",
			makeBad: func() []byte {
				return setBadValue(3, 0)
			},
			error: "invalid Hash id",
		},
		{
			name: "Bad OPRF",
			makeBad: func() []byte {
				return setBadValue(4, 0)
			},
			error: "invalid OPRF group id",
		},
		{
			name: "Bad AKE",
			makeBad: func() []byte {
				return setBadValue(5, 0)
			},
			error: "invalid AKE group id",
		},
	}

	convertToBadConf := func(encoded []byte) *opaque.Configuration {
		return &opaque.Configuration{
			KSF: opaque.KSFConfiguration{
				Identifier: ksf.Identifier(encoded[0]),
			},
			KDF:     crypto.Hash(encoded[1]),
			MAC:     crypto.Hash(encoded[2]),
			OPRF:    opaque.Group(encoded[4]),
			Hash:    crypto.Hash(encoded[3]),
			AKE:     opaque.Group(encoded[5]),
			Context: encoded[5:],
		}
	}

	for _, badConf := range tests {
		t.Run(badConf.name, func(t *testing.T) {
			// Test Deserialization for bad conf
			badEncoded := badConf.makeBad()
			_, err := opaque.DeserializeConfiguration(badEncoded)
			if err == nil || !strings.EqualFold(err.Error(), badConf.error) {
				t.Fatalf(
					"Expected error for %s. Want %q, got %q.\n\tEncoded: %v",
					badConf.name,
					badConf.error,
					err,
					badEncoded,
				)
			}

			// Test bad configuration for client, server, and deserializer setup
			bad := convertToBadConf(badEncoded)

			_, err = bad.Client()
			if err == nil || !strings.EqualFold(err.Error(), badConf.error) {
				t.Fatalf("Expected error for %s / client. Want %q, got %q", badConf.name, badConf.error, err)
			}

			_, err = bad.Server()
			if err == nil || !strings.EqualFold(err.Error(), badConf.error) {
				t.Fatalf("Expected error for %s / server. Want %q, got %q", badConf.name, badConf.error, err)
			}

			_, err = bad.Deserializer()
			if err == nil || !strings.EqualFold(err.Error(), badConf.error) {
				t.Fatalf("Expected error for %s / deserializer. Want %q, got %q", badConf.name, badConf.error, err)
			}
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
		KDF:     0,
		MAC:     0,
		Hash:    0,
		KSF:     opaque.KSFConfiguration{},
		AKE:     0,
		Context: nil,
	}

	if _, err := conf.GetFakeRecord(nil); err == nil {
		t.Fatal("expected error on invalid configuration")
	}
}
