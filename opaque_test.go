package opaque

import (
	"bytes"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/voprf"
	"testing"
)

func TestFull(t *testing.T) {
	modes := []envelope.Mode{envelope.Internal, envelope.External}

	p := &Parameters{
		OprfCiphersuite: voprf.RistrettoSha512,
		KDF:             hash.SHA512,
		MAC:             hash.SHA512,
		Hash:            hash.SHA512,
		MHF:             mhf.Scrypt,
		Group:           ciphersuite.Ristretto255Sha512,
		NonceLen:        32,
	}

	for _, mode := range modes {
		p.Mode = mode

		server := p.Server()
		serverSecretKey, serverPublicKey := server.KeyGen()

		ids := []byte("server")
		username := []byte("client")
		password := []byte("password")

		/*
			Registration
		*/

		// Client
		client := p.Client()
		reqReg := client.RegistrationStart(password)

		// Server
		respReg, kU, err := server.RegistrationResponse(reqReg, serverPublicKey, nil)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		// Client
		clientCreds := &envelope.Credentials{
			Idc: username,
			Ids: ids,
		}

		if mode == envelope.External {
			clientSecretKey, clientPublicKey := client.KeyGen()
			clientCreds.Skx = clientSecretKey
			clientCreds.Pkc = clientPublicKey
		}

		upload, exportKeyReg, err := client.RegistrationFinalize(clientCreds, respReg)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		// Server
		credFile := &CredentialFile{
			Ku:       kU,
			Pkc:      upload.Pku,
			Envelope: upload.Envelope,
		}

		/*
			Login
		*/

		// Client
		client = p.Client()
		ke1 := client.AuthenticationStart(password, nil)

		// Server
		server = p.Server()

		serverCreds := &envelope.Credentials{
			Skx: serverSecretKey,
			Pkc: upload.Pku,
			Pks: serverPublicKey,
			Idc: username,
			Ids: ids,
		}

		ke2, err := server.AuthenticationResponse(ke1, nil, credFile, serverCreds)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		// Client
		ke3, exportKeyLogin, err := client.AuthenticationFinalize(username, ids, ke2)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		// Server
		if err := server.AuthenticationFinalize(ke3); err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		// Check values
		if !bytes.Equal(exportKeyReg, exportKeyLogin) {
			t.Errorf("mode %v: export keys differ", mode)
		}

		clientKey := client.SessionKey()
		serverKey := server.SessionKey()

		if !bytes.Equal(clientKey, serverKey) {
			t.Fatalf("ùode %v: session keys differ", mode)
		}
	}
}
