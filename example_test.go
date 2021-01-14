package opaque

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

var exampleTestClient *Client

func receiveResponseFromServer(rreq []byte) ([]byte, message.Credentials) {
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

	r, err := enc.Decode(rreq, &message.RegistrationRequest{})
	if err != nil {
		panic(err)
	}

	req, ok := r.(*message.RegistrationRequest)
	if !ok {
		panic("")
	}

	// Evaluate the request and respond.
	resp, err := server.RegistrationResponse(req, enc)
	if err != nil {
		panic(err)
	}

	encResp, err := enc.Encode(resp)
	if err != nil {
		panic(err)
	}

	creds := &message.CustomCleartextCredentials{
		Pks: akeKeys.PublicKey,
		Idu: idu,
		Ids: ids,
	}

	return encResp, creds
}

func ExampleClient_registration() {
	password := []byte("password")

	p := &Parameters{
		Ciphersuite: voprf.RistrettoSha512,
		Hash:        hash.SHA256,
		AKE:         ake.TripleDH,
		Encoding:    encoding.JSON,
		MHF:         mhf.Argon2id.DefaultParameters(),
	}

	// Set up the client
	client := p.Client()

	// Prepare the registration request
	req := client.RegistrationStart(password)

	encReq, err := p.Encoding.Encode(req)
	if err != nil {
		panic(err)
	}

	// encodedReq must be send to the server. The server part is not covered here, this is a mock function.
	encodedResp, creds := receiveResponseFromServer(encReq)
	r, err := p.Encoding.Decode(encodedResp, &message.RegistrationResponse{})
	if err != nil {
		panic(err)
	}

	resp, ok := r.(*message.RegistrationResponse)
	if !ok {
		panic("")
	}

	// Create a secret and public key for the client.
	clientAkeSecretKey, clientAkePublicKey := client.AkeKeyGen()

	// Finalize the registration for the client, and send the output to the server.
	upload, _, err := client.RegistrationFinalize(clientAkeSecretKey, clientAkePublicKey, creds, resp, p.Encoding)
	if err != nil {
		panic(err)
	}

	encodedUpload, err := p.Encoding.Encode(upload)
	if encodedUpload == nil || err != nil {
		panic(err)
	}
	// Output:
}

func receiveRequestFromClient() []byte {
	password := []byte("password")

	p := &Parameters{
		Ciphersuite: voprf.RistrettoSha512,
		Hash:        hash.SHA256,
		AKE:         ake.TripleDH,
		Encoding:    encoding.JSON,
		MHF:         mhf.Argon2id.DefaultParameters(),
	}

	// Set up the client
	exampleTestClient = p.Client()

	// Prepare the registration request
	req := exampleTestClient.RegistrationStart(password)

	encReq, err := p.Encoding.Encode(req)
	if err != nil {
		panic(err)
	}

	return encReq
}

func receiveUploadFromClient(encodedResp []byte, creds message.Credentials) []byte {
	enc := encoding.JSON

	r, err := enc.Decode(encodedResp, &message.RegistrationResponse{})
	if err != nil {
		panic(err)
	}

	resp, ok := r.(*message.RegistrationResponse)
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
	username := []byte("user")
	ids := []byte("server")

	p := &Parameters{
		Ciphersuite: voprf.RistrettoSha512,
		Hash:        hash.SHA256,
		AKE:         ake.TripleDH,
		Encoding:    encoding.JSON,
	}

	// This can be set up before protocol execution
	oprfKeys := p.Ciphersuite.KeyGen()
	akeKeys := p.Ciphersuite.KeyGen()

	// Receive the request from the client and decode it.
	encodedReq := receiveRequestFromClient()

	r, err := p.Encoding.Decode(encodedReq, &message.RegistrationRequest{})
	if err != nil {
		panic(err)
	}

	req, ok := r.(*message.RegistrationRequest)
	if !ok {
		panic("")
	}

	// Set up the server.
	server := NewServer(p.Ciphersuite, p.Hash, p.AKE, oprfKeys.SecretKey, akeKeys.SecretKey, akeKeys.PublicKey)

	// Evaluate the request and respond.
	resp, err := server.RegistrationResponse(req, p.Encoding)
	if err != nil {
		panic(err)
	}

	encResp, err := p.Encoding.Encode(resp)
	if err != nil {
		panic(err)
	}

	// Receive the client envelope.
	creds := &message.CustomCleartextCredentials{
		Mode: envelope.CustomIdentifier,
		Pks:  akeKeys.PublicKey,
		Idu:  utils.RandomBytes(32),
		Ids:  ids,
	}
	encodedUpload := receiveUploadFromClient(encResp, creds)

	up, err := p.Encoding.Decode(encodedUpload, &message.RegistrationUpload{})
	if err != nil {
		panic(err)
	}

	upload, ok := up.(*message.RegistrationUpload)
	if !ok {
		panic("")
	}

	// Identifiers are not covered in OPAQUE. One way to deal with them is to have a human readable "display username"
	// that can be changed, and an immutable user identifier.
	userRecord, akeRecord, err := server.RegistrationFinalize(username, creds.Idu, creds.Ids, p, upload, p.Encoding)
	if err != nil {
		panic(err)
	}
	Users[string(username)] = userRecord
	AkeRecords[string(akeRecord.ID)] = akeRecord
	// Output:
}

func TestFull(t *testing.T) {
	p := &Parameters{
		Ciphersuite: voprf.RistrettoSha512,
		Hash:        hash.SHA256,
		AKE:         ake.TripleDH,
		Encoding:    encoding.JSON,
		MHF:         mhf.Argon2id.DefaultParameters(),
	}

	mode := envelope.Base

	ids := []byte("server")

	var serverSecretKey, serverPublicKey []byte

	switch p.AKE {
	case ake.TripleDH:
		serverAkeKeys := p.Ciphersuite.KeyGen()
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

	// Client : send username + reqReg to server
	username := []byte("user")
	password := []byte("password")
	c := p.Client()
	reqReg := c.RegistrationStart(password)

	// Server
	uuid := utils.RandomBytes(32)
	serverOprfKeys := p.Ciphersuite.KeyGen()
	server := NewServer(p.Ciphersuite, p.Hash, p.AKE, serverOprfKeys.SecretKey, serverSecretKey, serverPublicKey)

	respReg, err := server.RegistrationResponse(reqReg, p.Encoding)
	if err != nil {
		panic(err)
	}

	var creds message.Credentials
	switch mode {
	case envelope.Base:
		creds = message.NewClearTextCredentials(envelope.Base, serverPublicKey)
	case envelope.CustomIdentifier:
		creds = message.NewClearTextCredentials(envelope.CustomIdentifier, serverPublicKey, uuid, ids)
	}

	// Client
	var clientSecretKey, clientPublicKey []byte

	switch p.AKE {
	case ake.TripleDH:
		clientSecretKey, clientPublicKey = c.AkeKeyGen()
	case ake.SigmaI:
		sig := signature.Ed25519.New()
		_ = sig.GenerateKey()
		clientSecretKey = sig.GetPrivateKey()
		clientPublicKey = sig.GetPublicKey()
	}

	upload, _, err := c.RegistrationFinalize(clientSecretKey, clientPublicKey, creds, respReg, p.Encoding)
	if err != nil {
		panic(err)
	}

	// Server
	userRecord, akeRecord, err := server.RegistrationFinalize(username, uuid, ids, p, upload, p.Encoding)
	if err != nil {
		panic(err)
	}
	Users[string(username)] = userRecord
	AkeRecords[string(akeRecord.ID)] = akeRecord

	/*
		Authentication + Key Exchange
	*/

	// Client
	c = p.Client()
	req, err := c.AuthenticationStart(password, nil, p.Encoding)
	if err != nil {
		panic(err)
	}

	// Server
	user := Users[string(username)]
	p = &user.Parameters
	ar := AkeRecords[string(user.ServerAkeID)]
	server = user.Server()
	//server = NewServer(user.OprfSuite, h, ar.Ake, user.OprfSecret, ar.SecretKey, ar.PublicKey)
	env, err := envelope.DecodeEnvelope(user.Envelope, p.Encoding)
	if err != nil {
		panic(err)
	}

	creds = message.NewClearTextCredentials(envelope.Base, ar.PublicKey, user.UUID, user.ServerID)

	respCreds, err := server.AuthenticationResponse(req, env, creds, nil, nil, user.UserPublicKey, p.Encoding)
	if err != nil {
		panic(err)
	}

	// Client
	fin, _, err := c.AuthenticationFinalize(creds, respCreds, p.Encoding)
	if err != nil {
		panic(err)
	}

	// Server
	if err := server.AuthenticationFinalize(fin, p.Encoding); err != nil {
		panic(err)
	}

	// Verify session keys
	clientKey := c.SessionKey()
	serverKey := server.SessionKey()

	if bytes.Equal(clientKey, serverKey) {
		fmt.Println("Session secrets match !!!")
	} else {
		fmt.Println("Session secrets don't match.")
	}
	// Output: Session secrets match !!!
}
