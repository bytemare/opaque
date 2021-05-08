package opaque_test

import (
	"bytes"
	"testing"

	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal/core/envelope"
	"github.com/bytemare/opaque/message"
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

	test := &testParams{
		Configuration: p,
		username:      username,
		userID:        opaque.CredentialIdentifier(utils.RandomBytes(32)),
		serverID:      ids,
		password:      password,
		oprfSeed:      utils.RandomBytes(32),
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

func testRegistration(t *testing.T, p *testParams) (*message.RegistrationUpload, []byte) {
	// Client
	client := p.Client()
	reqReg := client.RegistrationInit(p.password)
	m1s := reqReg.Serialize()

	// Server
	server := p.Server()
	m1, err := server.DeserializeRegistrationRequest(m1s)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	respReg, _, err := server.RegistrationResponse(m1, p.serverPublicKey, p.userID, p.oprfSeed)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	m2s := respReg.Serialize()

	// Client
	clientCreds := &envelope.Credentials{
		Idc: p.username,
		Ids: p.serverID,
	}

	var clientSecretKey []byte
	if p.Mode == opaque.External {
		clientSecretKey, _ = client.KeyGen()
	}

	m2, err := client.DeserializeRegistrationResponse(m2s)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	upload, exportKeyReg, err := client.RegistrationFinalize(clientSecretKey, clientCreds, m2)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	m3s := upload.Serialize()

	// Server
	m3, err := server.DeserializeRegistrationUpload(m3s)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	return m3, exportKeyReg
}

func testAuthentication(t *testing.T, p *testParams, record *message.RegistrationUpload) []byte {
	// Client
	client := p.Client()
	ke1 := client.Init(p.password, nil)

	m4s := ke1.Serialize()

	// Server
	server := p.Server()

	serverCreds := &envelope.Credentials{
		Idc:          p.username,
		Ids:          p.serverID,
		MaskingNonce: utils.RandomBytes(32),
	}

	m4, err := server.DeserializeKE1(m4s)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	ke2, err := server.Init(m4, nil, p.serverSecretKey, p.serverPublicKey, record, serverCreds, p.userID, p.oprfSeed)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	m5s := ke2.Serialize()

	// Client
	m5, err := client.DeserializeKE2(m5s)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	ke3, exportKeyLogin, err := client.Finish(p.username, p.serverID, m5)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	m6s := ke3.Serialize()

	// Server
	m6, err := server.DeserializeKE3(m6s)
	if err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	if err := server.Finish(m6); err != nil {
		t.Fatalf(dbgErr, p.Mode, err)
	}

	clientKey := client.SessionKey()
	serverKey := server.SessionKey()

	if !bytes.Equal(clientKey, serverKey) {
		t.Fatalf("mode %v: session keys differ", p.Mode)
	}

	return exportKeyLogin
}
