// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
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
	record, exportKeyReg := testRegistration(t, test)

	/*
		Login
	*/
	exportKeyLogin := testAuthentication(t, test, record)

	// Check values
	if !bytes.Equal(exportKeyReg, exportKeyLogin) {
		t.Errorf("export keys differ")
	}
}

func testRegistration(t *testing.T, p *testParams) (*opaque.ClientRecord, []byte) {
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

		upload, key := client.RegistrationFinalize(m2, p.username, p.serverID)
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

		return &opaque.ClientRecord{
			CredentialIdentifier: credID,
			ClientIdentity:       p.username,
			RegistrationRecord:   m3,
		}, exportKeyReg
	}
}

func testAuthentication(t *testing.T, p *testParams, record *opaque.ClientRecord) []byte {
	// Client
	client, _ := p.Client()

	var m4s []byte
	{
		ke1 := client.LoginInit(p.password)
		m4s = ke1.Serialize()
	}

	// Server
	var m5s []byte
	var state []byte
	{
		server, _ := p.Server()
		m4, err := server.Deserialize.KE1(m4s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		ke2, err := server.LoginInit(m4, p.serverID, p.serverSecretKey, p.serverPublicKey, p.oprfSeed, record)
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

		ke3, key, err := client.LoginFinish(p.username, p.serverID, m5)
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
		server, _ := p.Server()
		m6, err := server.Deserialize.KE3(m6s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		if err := server.SetAKEState(state); err != nil {
			t.Fatalf(dbgErr, err)
		}

		if err := server.LoginFinish(m6); err != nil {
			t.Fatalf(dbgErr, err)
		}

		serverKey = server.SessionKey()
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatalf(" session keys differ")
	}

	return exportKeyLogin
}
