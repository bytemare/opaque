package opaque

//var exampleTestClient *Client
//
//func receiveResponseFromServer(rreq []byte) ([]byte, message.cleartextCredentials) {
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
