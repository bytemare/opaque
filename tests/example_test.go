package opaque_test

//
//import (
//	"github.com/bytemare/cryptotools/encoding"
//	"github.com/bytemare/cryptotools/group/ciphersuite"
//	"github.com/bytemare/cryptotools/hash"
//	"github.com/bytemare/cryptotools/mhf"
//	"github.com/bytemare/cryptotools/utils"
//	"github.com/bytemare/opaque"
//	"github.com/bytemare/opaque/internal/core/envelope"
//	"github.com/bytemare/opaque/message"
//	"github.com/bytemare/voprf"
//)
//
//var exampleTestClient *opaque.Client
//
//func receiveResponseFromServer(rreq []byte) []byte {
//	idu := []byte("user")
//	ids := []byte("server")
//
//	p := &opaque.Configuration{
//		OprfCiphersuite: voprf.RistrettoSha512,
//		KDF:             hash.SHA512,
//		MAC:             hash.SHA512,
//		Hash:            hash.SHA512,
//		MHF:             mhf.Scrypt,
//		Mode: 			 envelope.Internal,
//		AKEGroup:        ciphersuite.Ristretto255Sha512,
//		NonceLen:        32,
//	}
//
//	server := p.Server()
//	serverSecretKey, serverPublicKey := p.Server().KeyGen()
//
//	// Set up the server.
//	m1, err := server.DeserializeRegistrationRequest(rreq)
//	if err != nil {
//		panic(err)
//	}
//
//	respReg, _, err := server.RegistrationResponse(m1, serverPublicKey, p.userID, p.oprfSeed)
//	if err != nil {
//		panic(err)
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
//	creds := &message.customCleartextCredentials{
//		Pks: akeKeys.PublicKey,
//		Idu: idu,
//		Ids: ids,
//	}
//
//	return encResp, creds
//}
//
//func ExampleClient_registration() {
//	ids := []byte("server")
//	username := []byte("client")
//	password := []byte("password")
//
//	p := &opaque.Configuration{
//		OprfCiphersuite: voprf.RistrettoSha512,
//		KDF:             hash.SHA512,
//		MAC:             hash.SHA512,
//		Hash:            hash.SHA512,
//		MHF:             mhf.Scrypt,
//		Mode: 			 envelope.Internal,
//		AKEGroup:        ciphersuite.Ristretto255Sha512,
//		NonceLen:        32,
//	}
//
//	clientCreds := &envelope.Credentials{
//		Idc: username,
//		Ids: ids,
//	}
//
//	// Set up the client
//	client := p.Client()
//
//	// Prepare the registration request
//	reg := client.RegistrationInit(password)
//	message1 := reg.Serialize()
//
//	// message1 must be send to the server. The server part is not covered here, this is a mock function.
//	encodedResp := receiveResponseFromServer(message1)
//
//	// deserialize the server response
//	regResp, err := client.DeserializeRegistrationResponse(encodedResp)
//	if err != nil {
//		panic(err)
//	}
//
//	// Finalize the registration for the client
//	upload, _, err := client.RegistrationFinalize(nil, clientCreds, regResp)
//	if err != nil {
//		panic(err)
//	}
//
//	// Send the upload message securely to the server
//
//	_ = upload.Serialize()
//	// Output:
//}
//
//func receiveRequestFromClient() []byte {
//	password := []byte("password")
//
//	p := &Configuration{
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
//	req := exampleTestClient.RegistrationInit(password)
//
//	encReq, err := p.Encoding.Encode(req)
//	if err != nil {
//		panic(err)
//	}
//
//	return encReq
//}
//
//func receiveUploadFromClient(encodedResp []byte, creds message.cleartextCredentials) []byte {
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
//	p := &Configuration{
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
//	creds := &message.customCleartextCredentials{
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
