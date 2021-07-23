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

const dbgErr = "Mode %v: %v"

type testParams struct {
	*opaque.Configuration
	username, userID, serverID, password, serverSecretKey, serverPublicKey, oprfSeed []byte
}

func TestFull(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")
	password := []byte("password")

	modes := []opaque.Mode{opaque.Internal, opaque.External}

	p := opaque.DefaultConfiguration()
	p.Context = []byte("OPAQUETest")

	test := &testParams{
		Configuration: p,
		username:      username,
		userID:        username,
		serverID:      ids,
		password:      password,
		oprfSeed:      internal.RandomBytes(32),
	}

	for _, mode := range modes {
		test.Mode = mode
		serverSecretKey, serverPublicKey := p.Server().KeyGen()
		test.serverSecretKey = serverSecretKey
		test.serverPublicKey = serverPublicKey

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
			t.Errorf("mode %v: export keys differ", mode)
		}

	}
}

func testRegistration(t *testing.T, p *testParams) (*opaque.ClientRecord, []byte) {
	// Client
	client := p.Client()

	var m1s []byte
	{
		reqReg := client.RegistrationInit(p.password)
		m1s = reqReg.Serialize()
	}

	// Server
	var m2s []byte
	var credID []byte
	{
		server := p.Server()
		m1, err := server.DeserializeRegistrationRequest(m1s)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		credID = internal.RandomBytes(32)
		respReg, err := server.RegistrationResponse(m1, p.serverPublicKey, credID, p.oprfSeed)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		m2s = respReg.Serialize()
	}

	// Client
	var m3s []byte
	var exportKeyReg []byte
	{
		clientCreds := &opaque.Credentials{
			Client: p.username,
			Server: p.serverID,
		}

		var clientSecretKey []byte
		if p.Mode == opaque.External {
			clientSecretKey, _ = client.KeyGen()
		}

		m2, err := client.DeserializeRegistrationResponse(m2s)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		upload, key, err := client.RegistrationFinalize(clientSecretKey, clientCreds, m2)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}
		exportKeyReg = key

		m3s = upload.Serialize()
	}

	// Server
	{
		server := p.Server()
		m3, err := server.DeserializeRegistrationUpload(m3s)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		return &opaque.ClientRecord{
			CredentialIdentifier: credID,
			ClientIdentity:       p.username,
			RegistrationUpload:   m3,
		}, exportKeyReg
	}
}

func testAuthentication(t *testing.T, p *testParams, record *opaque.ClientRecord) []byte {
	// Client
	client := p.Client()

	var m4s []byte
	{
		ke1 := client.Init(p.password)
		m4s = ke1.Serialize()
	}

	// Server
	var m5s []byte
	var state []byte
	{
		server := p.Server()
		m4, err := server.DeserializeKE1(m4s)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		ke2, err := server.Init(m4, p.serverID, p.serverSecretKey, p.serverPublicKey, p.oprfSeed, record)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		state = server.SerializeState()

		m5s = ke2.Serialize()
	}

	// Client
	var m6s []byte
	var exportKeyLogin []byte
	var clientKey []byte
	{
		m5, err := client.DeserializeKE2(m5s)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		ke3, key, err := client.Finish(p.username, p.serverID, m5)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}
		exportKeyLogin = key

		m6s = ke3.Serialize()
		clientKey = client.SessionKey()
	}

	// Server
	var serverKey []byte
	{
		server := p.Server()
		m6, err := server.DeserializeKE3(m6s)
		if err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		if err := server.DeserializeAKEState(state); err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		if err := server.Finish(m6); err != nil {
			t.Fatalf(dbgErr, p.Mode, err)
		}

		serverKey = server.SessionKey()
	}

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatalf("mode %v: session keys differ", p.Mode)
	}

	return exportKeyLogin
}
