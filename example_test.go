package opaque

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/voprf"
)

//var exampleTestClient *Client
//
//func receiveResponseFromServer(rreq []byte) ([]byte, message.CleartextCredentials) {
//	idu := []byte("user")
//	ids := []byte("server")
//
//	suite := voprf.RistrettoSha512
//	h := hash.SHA256
//	ke := ake.SigmaI
//	enc := encoding.JSON
//
//	oprfKeys := suite.KeyGen()
//	akeKeys := suite.KeyGen()
//
//	// Set up the server.
//	server := NewServer(suite, h, ke, oprfKeys.SecretKey, akeKeys.SecretKey, akeKeys.PublicKey)
//
//	r, err := enc.Decode(rreq, &message.RegistrationRequest{})
//	if err != nil {
//		panic(err)
//	}
//
//	req, ok := r.(*message.RegistrationRequest)
//	if !ok {
//		panic("")
//	}
//
//	// Evaluate the request and respond.
//	resp, err := server.RegistrationResponse(req, enc)
//	if err != nil {
//		panic(err)
//	}
//
//	encResp, err := enc.Encode(resp)
//	if err != nil {
//		panic(err)
//	}
//
//	creds := &message.CustomCleartextCredentials{
//		Pks: akeKeys.PublicKey,
//		Idu: idu,
//		Ids: ids,
//	}
//
//	return encResp, creds
//}
//
//func ExampleClient_registration() {
//	password := []byte("password")
//
//	p := &Parameters{
//		OprfCiphersuite: voprf.RistrettoSha512,
//		Hash:            hash.SHA256,
//		AKE:             ake.TripleDH,
//		Encoding:        encoding.JSON,
//		MHF:             mhf.Argon2id.DefaultParameters(),
//	}
//
//	// Set up the client
//	client := p.Client()
//
//	// Prepare the registration request
//	req := client.RegistrationStart(password)
//
//	encReq, err := p.Encoding.Encode(req)
//	if err != nil {
//		panic(err)
//	}
//
//	// encodedReq must be send to the server. The server part is not covered here, this is a mock function.
//	encodedResp, creds := receiveResponseFromServer(encReq)
//	r, err := p.Encoding.Decode(encodedResp, &message.RegistrationResponse{})
//	if err != nil {
//		panic(err)
//	}
//
//	resp, ok := r.(*message.RegistrationResponse)
//	if !ok {
//		panic("")
//	}
//
//	// Create a secret and public key for the client.
//	clientAkeSecretKey, clientAkePublicKey := client.AkeKeyGen()
//
//	// Finalize the registration for the client, and send the output to the server.
//	upload, _, err := client.RegistrationFinalize(clientAkeSecretKey, clientAkePublicKey, creds, resp, p.Encoding)
//	if err != nil {
//		panic(err)
//	}
//
//	encodedUpload, err := p.Encoding.Encode(upload)
//	if encodedUpload == nil || err != nil {
//		panic(err)
//	}
//	// Output:
//}
//
//func receiveRequestFromClient() []byte {
//	password := []byte("password")
//
//	p := &Parameters{
//		OprfCiphersuite: voprf.RistrettoSha512,
//		Hash:            hash.SHA256,
//		AKE:             ake.TripleDH,
//		Encoding:        encoding.JSON,
//		MHF:             mhf.Argon2id.DefaultParameters(),
//	}
//
//	// Set up the client
//	exampleTestClient = p.Client()
//
//	// Prepare the registration request
//	req := exampleTestClient.RegistrationStart(password)
//
//	encReq, err := p.Encoding.Encode(req)
//	if err != nil {
//		panic(err)
//	}
//
//	return encReq
//}
//
//func receiveUploadFromClient(encodedResp []byte, creds message.CleartextCredentials) []byte {
//	enc := encoding.JSON
//
//	r, err := enc.Decode(encodedResp, &message.RegistrationResponse{})
//	if err != nil {
//		panic(err)
//	}
//
//	resp, ok := r.(*message.RegistrationResponse)
//	if !ok {
//		panic("")
//	}
//
//	// Create a secret and public key for the client.
//	clientAkeSecretKey, clientAkePublicKey := exampleTestClient.AkeKeyGen()
//
//	// Finalize the registration for the client, and send the output to the server.
//	upload, _, err := exampleTestClient.RegistrationFinalize(clientAkeSecretKey, clientAkePublicKey, creds, resp, enc)
//	if err != nil {
//		panic(err)
//	}
//
//	encodedUpload, err := enc.Encode(upload)
//	if err != nil {
//		panic(err)
//	}
//
//	return encodedUpload
//}
//
//func ExampleServer_registration() {
//	username := []byte("user")
//	ids := []byte("server")
//
//	p := &Parameters{
//		OprfCiphersuite: voprf.RistrettoSha512,
//		Hash:            hash.SHA256,
//		AKE:             ake.TripleDH,
//		Encoding:        encoding.JSON,
//	}
//
//	// This can be set up before protocol execution
//	oprfKeys := p.OprfCiphersuite.KeyGen()
//	akeKeys := p.OprfCiphersuite.KeyGen()
//
//	// Receive the request from the client and decode it.
//	encodedReq := receiveRequestFromClient()
//
//	r, err := p.Encoding.Decode(encodedReq, &message.RegistrationRequest{})
//	if err != nil {
//		panic(err)
//	}
//
//	req, ok := r.(*message.RegistrationRequest)
//	if !ok {
//		panic("")
//	}
//
//	// Set up the server.
//	server := NewServer(p.OprfCiphersuite, p.Hash, p.AKE, oprfKeys.SecretKey, akeKeys.SecretKey, akeKeys.PublicKey)
//
//	// Evaluate the request and respond.
//	resp, err := server.RegistrationResponse(req, p.Encoding)
//	if err != nil {
//		panic(err)
//	}
//
//	encResp, err := p.Encoding.Encode(resp)
//	if err != nil {
//		panic(err)
//	}
//
//	// Receive the client envelope.
//	creds := &message.CustomCleartextCredentials{
//		Mode: envelope.CustomIdentifier,
//		Pks:  akeKeys.PublicKey,
//		Idu:  utils.RandomBytes(32),
//		Ids:  ids,
//	}
//	encodedUpload := receiveUploadFromClient(encResp, creds)
//
//	up, err := p.Encoding.Decode(encodedUpload, &message.RegistrationUpload{})
//	if err != nil {
//		panic(err)
//	}
//
//	upload, ok := up.(*message.RegistrationUpload)
//	if !ok {
//		panic("")
//	}
//
//	// Identifiers are not covered in OPAQUE. One way to deal with them is to have a human readable "display username"
//	// that can be changed, and an immutable user identifier.
//	userRecord, akeRecord, err := server.RegistrationFinalize(username, creds.Idu, creds.Ids, p, upload, p.Encoding)
//	if err != nil {
//		panic(err)
//	}
//	poc.Users[string(username)] = userRecord
//	poc.AkeRecords[string(akeRecord.ID)] = akeRecord
//	// Output:
//}

func TestFull(t *testing.T) {
	p := &Parameters{
		OprfCiphersuite: voprf.RistrettoSha512,
		Mode:            envelope.CustomIdentifier,
		Hash:            hash.SHA256,
		AKE:             ake.TripleDH,
		NonceLen:        32,
	}

	m := mhf.Argon2id.DefaultParameters()

	ids := []byte("server")

	// Todo: it is not sure here what the client AKE secret is. HashToScalar on rwdu ? A secret RSA or ECDSA key ?
	// todo : hence, it's not sure what pku is

	/*
		Registration
	*/

	// Client : send username + reqReg to server
	username := []byte("user")
	password := []byte("password")
	client := p.Client(m)
	reqReg := client.RegistrationStart(password)

	// Server
	uuid := utils.RandomBytes(32)
	server := p.Server()
	serverSecretKey, serverPublicKey := server.KeyGen()
	respReg, kU, err := server.RegistrationResponse(reqReg, serverPublicKey, nil)
	if err != nil {
		panic(err)
	}

	// Send uuid, ids, respReg to client

	// Client
	clientSecretKey, clientPublicKey := client.KeyGen()

	creds := &envelope.Credentials{
		Sk:  clientSecretKey,
		Pk:  clientPublicKey,
		Idu: uuid,
		Ids: ids,
	}

	upload, _, err := client.RegistrationFinalize(creds, respReg)
	if err != nil {
		panic(err)
	}

	// Server

	a := &AkeRecord{
		ServerID:  ids,
		SecretKey: serverSecretKey,
		PublicKey: serverPublicKey,
	}

	file := &CredentialFile{
		Ku:       kU,
		Pku:      upload.Pku,
		Envelope: upload.Envelope,
	}

	user := &UserRecord{
		HumanUserID:    username,
		UUID:           uuid,
		ServerAkeID:    a.ServerID,
		CredentialFile: *file,
		Parameters:     *p,
	}

	/*
		Authentication + Key Exchange
	*/

	// Client
	client = p.Client(m)
	req := client.AuthenticationStart(password, nil)

	// Server
	p = &user.Parameters
	server = p.Server()

	serverCreds := &envelope.Credentials{
		Sk:  a.SecretKey,
		Pk:  a.PublicKey,
		Idu: user.UUID,
		Ids: a.ServerID,
	}

	respCreds, err := server.AuthenticationResponse(req, nil, &user.CredentialFile, serverCreds)
	if err != nil {
		panic(err)
	}

	// Client
	fin, _, err := client.AuthenticationFinalize(uuid, ids, respCreds)
	if err != nil {
		panic(err)
	}

	// Server
	if err := server.AuthenticationFinalize(fin); err != nil {
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
