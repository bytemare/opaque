package opaque

import (
	"bytes"
	"testing"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/voprf"
)

func TestFull(t *testing.T) {
	modes := []envelope.Mode{envelope.Internal, envelope.External}

	p := &Parameters{
		OprfCiphersuite: voprf.RistrettoSha512,
		KDF:             hash.SHA512,
		MAC:             hash.SHA512,
		Hash:            hash.SHA512,
		MHF:             mhf.Scrypt,
		AKEGroup:           ciphersuite.Ristretto255Sha512,
		NonceLen:        32,
	}

	for _, mode := range modes {
		p.Mode = mode

		server := p.Server()
		serverSecretKey, serverPublicKey := server.KeyGen()

		ids := []byte("server")
		username := []byte("client")
		password := []byte("password")

		userID := CredentialIdentifier(utils.RandomBytes(32))
		oprfSeed := utils.RandomBytes(32)

		/*
			Registration
		*/

		// Client
		client := p.Client()
		reqReg := client.RegistrationStart(password)
		m1s := reqReg.Serialize()

		// Server
		m1, err := server.DeserializeRegistrationRequest(m1s)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		respReg, _, err := server.RegistrationResponse(m1, serverPublicKey, userID, oprfSeed)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		m2s := respReg.Serialize()

		// Client
		clientCreds := &envelope.Credentials{
			Idc: username,
			Ids: ids,
		}

		var clientSecretKey []byte
		if mode == envelope.External {
			clientSecretKey, _ = client.KeyGen()
		}

		m2, err := client.DeserializeRegistrationResponse(m2s)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		upload, exportKeyReg, err := client.RegistrationFinalize(clientSecretKey, clientCreds, m2)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		m3s := upload.Serialize()

		// Server
		m3, err := server.DeserializeRegistrationUpload(m3s)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		/*
			Login
		*/

		// Client
		client = p.Client()
		ke1 := client.AuthenticationStart(password, nil)

		m4s := ke1.Serialize()

		// Server
		server = p.Server()

		serverCreds := &envelope.Credentials{
			Idc: username,
			Ids: ids,
			MaskingNonce: utils.RandomBytes(32),
		}

		m4, err := server.DeserializeKE1(m4s)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		ke2, err := server.AuthenticationResponse(m4, nil, serverSecretKey, serverPublicKey, m3, serverCreds, userID, oprfSeed)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		m5s := ke2.Serialize()

		// Client
		m5, err := client.DeserializeKE2(m5s)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		ke3, exportKeyLogin, err := client.AuthenticationFinalize(username, ids, m5)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		m6s := ke3.Serialize()

		// Server
		m6, err := server.DeserializeKE3(m6s)
		if err != nil {
			t.Fatalf("Mode %v: %v", mode, err)
		}

		if err := server.AuthenticationFinalize(m6); err != nil {
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
