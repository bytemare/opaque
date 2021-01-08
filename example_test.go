package opaque

import (
	"bytes"
	"fmt"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/records"
	"github.com/bytemare/voprf"
	"testing"
)

var exampleTestClient *Client

func receiveResponseFromServer(rreq []byte) ([]byte, Credentials) {
	idu := []byte("user")
	ids := []byte("server")

	suite := voprf.RistrettoSha512
	h := hash.SHA256
	ke := ake.SigmaI
	enc := encoding.JSON

	oprfKeys := suite.KeyGen()
	akeKeys := suite.KeyGen()

	// Set up the server.
	server := NewServer(suite, h, ke, oprfKeys.SecretKey, akeKeys.SecretKey, akeKeys.PublicKey)

	r, err := enc.Decode(rreq, &RegistrationRequest{})
	if err != nil {
		panic(err)
	}

	req, ok := r.(*RegistrationRequest)
	if !ok {
		panic("")
	}

	// Evaluate the request and respond.
	resp := server.RegistrationResponse(req, enc)

	encResp, err := enc.Encode(resp)
	if err != nil {
		panic(err)
	}

	creds := &CustomCleartextCredentials{
		Pks: akeKeys.PublicKey,
		Idu: idu,
		Ids: ids,
	}

	return encResp, creds
}

func ExampleClient_registration() {
	password := []byte("password")

	suite := voprf.RistrettoSha512
	h := hash.SHA256
	m := mhf.Argon2id
	ke := ake.SigmaI
	enc := encoding.JSON

	// Set up the client
	client := NewClient(suite, h, m, ke)

	// Prepare the registration request
	req := client.RegistrationStart(password)

	encReq, err := enc.Encode(req)
	if err != nil {
		panic(err)
	}

	// encodedReq must be send to the server. The server part is not covered here, this is a mock function.
	encodedResp, creds := receiveResponseFromServer(encReq)
	r, err := enc.Decode(encodedResp, &RegistrationResponse{})
	if err != nil {
		panic(err)
	}

	resp, ok := r.(*RegistrationResponse)
	if !ok {
		panic("")
	}

	// Create a secret and public key for the client.
	clientAkeSecretKey, clientAkePublicKey := client.AkeKeyGen()

	// Finalize the registration for the client, and send the output to the server.
	upload, _, err := client.RegistrationFinalize(clientAkeSecretKey, clientAkePublicKey, creds, resp, enc)
	if err != nil {
		panic(err)
	}

	encodedUpload, err := enc.Encode(upload)
	if encodedUpload == nil || err != nil {
		panic(err)
	}
	// Output:
}

func receiveRequestFromClient() []byte {
	password := []byte("password")

	suite := voprf.RistrettoSha512
	h := hash.SHA256
	m := mhf.Argon2id
	ke := ake.SigmaI
	enc := encoding.JSON

	// Set up the client
	exampleTestClient = NewClient(suite, h, m, ke)

	// Prepare the registration request
	req := exampleTestClient.RegistrationStart(password)

	encReq, err := enc.Encode(req)
	if err != nil {
		panic(err)
	}

	return encReq
}

func receiveUploadFromClient(encodedResp []byte, creds Credentials) []byte {
	enc := encoding.JSON

	r, err := enc.Decode(encodedResp, &RegistrationResponse{})
	if err != nil {
		panic(err)
	}

	resp, ok := r.(*RegistrationResponse)
	if !ok {
		panic("")
	}

	// Create a secret and public key for the client.
	clientAkeSecretKey, clientAkePublicKey := exampleTestClient.AkeKeyGen()

	// Finalize the registration for the client, and send the output to the server.
	upload, _, err := exampleTestClient.RegistrationFinalize(clientAkeSecretKey, clientAkePublicKey, creds, resp, enc)
	if err != nil {
		panic(err)
	}

	encodedUpload, err := enc.Encode(upload)
	if err != nil {
		panic(err)
	}

	return encodedUpload
}

func ExampleServer_registration() {
	idu := []byte("user")
	ids := []byte("server")

	suite := voprf.RistrettoSha512
	h := hash.SHA256
	ke := ake.SigmaI
	enc := encoding.JSON

	// This can be set up before protocol execution
	oprfKeys := suite.KeyGen()
	akeKeys := suite.KeyGen()

	// Receive the request from the client and decode it.
	encodedReq := receiveRequestFromClient()

	r, err := enc.Decode(encodedReq, &RegistrationRequest{})
	if err != nil {
		panic(err)
	}

	req, ok := r.(*RegistrationRequest)
	if !ok {
		panic("")
	}

	// Set up the server.
	server := NewServer(suite, h, ke, oprfKeys.SecretKey, akeKeys.SecretKey, akeKeys.PublicKey)

	// Evaluate the request and respond.
	resp := server.RegistrationResponse(req, enc)

	encResp, err := enc.Encode(resp)
	if err != nil {
		panic(err)
	}

	// Receive the client envelope.
	creds := &CustomCleartextCredentials{
		Pks: akeKeys.PublicKey,
		Idu: idu,
		Ids: ids,
	}
	encodedUpload := receiveUploadFromClient(encResp, creds)

	up, err := enc.Decode(encodedUpload, &RegistrationUpload{})
	if err != nil {
		panic(err)
	}

	upload, ok := up.(*RegistrationUpload)
	if !ok {
		panic("")
	}

	// Identifiers are not covered in OPAQUE. One way to deal with them is to have a human readable "display username"
	// that can be changed, and an immutable user identifier.
	username := idu
	uuid := utils.RandomBytes(32)
	userRecord, oprfRecord, akeRecord, err := server.RegistrationFinalize(username, uuid, upload, enc)
	if err != nil {
		panic(err)
	}
	records.Users[string(username)] = userRecord
	records.OprfRecords[string(oprfRecord.ID)] = oprfRecord
	records.AkeRecords[string(akeRecord.ID)] = akeRecord
	// Output:
}

func TestFull(t *testing.T) {
	suite := voprf.RistrettoSha512
	h := hash.SHA256
	m := mhf.Argon2id
	ke := ake.SigmaI
	enc := encoding.JSON

	idu := []byte("user")
	ids := []byte("server")
	password := []byte("password")
	serverOprfKeys := suite.KeyGen()

	var serverSecretKey, serverPublicKey []byte

	switch ke {
	case ake.TripleDH:
		serverAkeKeys := suite.KeyGen()
		serverSecretKey = serverAkeKeys.SecretKey
		serverPublicKey = serverAkeKeys.PublicKey
	case ake.SigmaI:
		sig := signature.Ed25519.New()
		_ = sig.GenerateKey()
		serverSecretKey = sig.GetPrivateKey()
		serverPublicKey = sig.GetPublicKey()
	}


	// Todo: it is not sure here what the client AKE secret is. HashToScalar on rwdu ? A secret RSA or ECDSA key ?
	// todo : hence, it's not sure what pku is

	/*
		Registration
	*/

	// Client
	client := NewClient(suite, h, m, ke)
	username := idu
	reqReg := client.RegistrationStart(password)

	// Server
	server := NewServer(suite, h, ke, serverOprfKeys.SecretKey, serverSecretKey, serverPublicKey)
	respReg := server.RegistrationResponse(reqReg, enc)
	uuid := utils.RandomBytes(32)
	creds := &CustomCleartextCredentials{
		Pks: serverPublicKey,
		Idu: uuid,
		Ids: ids,
	}

	// Client
	var clientSecretKey, clientPublicKey []byte

	switch ke {
	case ake.TripleDH:
		clientSecretKey, clientPublicKey = client.AkeKeyGen()
	case ake.SigmaI:
		sig := signature.Ed25519.New()
		_ = sig.GenerateKey()
		clientSecretKey = sig.GetPrivateKey()
		clientPublicKey = sig.GetPublicKey()
	}

	upload, _, err := client.RegistrationFinalize(clientSecretKey, clientPublicKey, creds, respReg, enc)
	if err != nil {
		panic(err)
	}

	// Server
	userRecord, oprfRecord, akeRecord, err := server.RegistrationFinalize(username, uuid, upload, enc)
	if err != nil {
		panic(err)
	}
	records.Users[string(username)] = userRecord
	records.OprfRecords[string(oprfRecord.ID)] = oprfRecord
	records.AkeRecords[string(akeRecord.ID)] = akeRecord

	/*
		Authentication + Key Exchange
	*/

	// Client
	client = NewClient(suite, h, m, ke)
	username = idu
	req := client.AuthenticationStart(password, nil, enc)

	// Server
	ur := records.Users[string(username)]
	or := records.OprfRecords[string(ur.ServerOprfID)]
	ar := records.AkeRecords[string(ur.ServerAkeID)]

	server = NewServer(or.Ciphersuite, h, ar.Ake, or.OprfKey, ar.SecretKey, ar.PublicKey)
	env, err := DecodeEnvelope(ur.Envelope, enc)
	if err != nil {
		panic(err)
	}

	resp := server.AuthenticationResponse(req, env, ur.UUID, ur.UserPublicKey, ids, nil, nil, enc)
	creds = &CustomCleartextCredentials{
		Pks: ar.PublicKey,
		Idu: ur.UUID,
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

	if bytes.Equal(clientKey, serverKey) {
		fmt.Println("Session secrets match !!!")
	} else {
		fmt.Println("Session secrets don't match.")
	}
	// Output: Session secrets match !!!
}
