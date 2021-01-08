package opaque

import (
	"bytes"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/records"
	"github.com/bytemare/voprf"
	"testing"
)

var (
	oprfSuites = []voprf.Ciphersuite{
		voprf.RistrettoSha512, voprf.P256Sha256, voprf.P384Sha512, voprf.P521Sha512,
	}
	akes = []ake.Identifier{ake.SigmaI, ake.TripleDH}
)

func gen3DHkeys(suite voprf.Ciphersuite) (sk, pk []byte) {
	serverAkeKeys := suite.KeyGen()
	return serverAkeKeys.SecretKey, serverAkeKeys.PublicKey
}

func genSigmaKeys(sig signature.Identifier) (sk, pk []byte) {
	s := sig.New()
	_ = s.GenerateKey()
	return s.GetPrivateKey(), s.GetPublicKey()
}

func registration(t *testing.T, client *Client, server *Server, idu, password, sku, pku, ids, serverPk []byte, enc encoding.Encoding) *RegistrationUpload {
	// Client start
	reqReg := client.RegistrationStart(password)

	// Server response
	respReg := server.RegistrationResponse(reqReg, enc)
	creds := &CustomCleartextCredentials{
		Pks: serverPk,
		Idu: idu,
		Ids: ids,
	}

	// Client
	upload, _, err := client.RegistrationFinalize(sku, pku, creds, respReg, enc)
	if err != nil {
		panic(err)
	}

	// Server
	username := idu
	uuid := utils.RandomBytes(32)
	userRecord, oprfRecord, akeRecord, err := server.RegistrationFinalize(username, uuid, upload, enc)
	if err != nil {
		panic(err)
	}
	records.Users[string(username)] = userRecord
	records.OprfRecords[string(oprfRecord.ID)] = oprfRecord
	records.AkeRecords[string(akeRecord.ID)] = akeRecord

	return upload
}

func authentication(t *testing.T, client *Client, server *Server, idu, password, ids, pks []byte, userRecord *RegistrationUpload, enc encoding.Encoding) bool {
	// Client
	req := client.AuthenticationStart(password, nil, enc)

	// Server
	resp := server.AuthenticationResponse(req, &userRecord.Envelope, userRecord.Pku, idu, ids, nil, nil, enc)
	creds := &CustomCleartextCredentials{
		Pks: pks,
		Idu: idu,
		Ids: ids,
	}

	// Client
	fin, _, err := client.AuthenticationFinalize(creds, resp, nil, enc)
	if err != nil {
		panic(err)
	}

	// Server
	if err := server.AuthenticationFinalize(fin, enc); err != nil {
		panic(err)
	}

	// Verify session keys
	clientKey := client.SessionKey()
	serverKey := server.SessionKey()

	return bytes.Equal(clientKey, serverKey)
}