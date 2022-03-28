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
	"crypto"
	"fmt"
	"log"

	"github.com/bytemare/crypto/ksf"
	"github.com/bytemare/opaque"
)

var (
	exampleClientRecord                               *opaque.ClientRecord
	secretOprfSeed, serverPrivateKey, serverPublicKey []byte
)

func isSameConf(a, b *opaque.Configuration) bool {
	if a.OPRF != b.OPRF {
		return false
	}
	if a.KDF != b.KDF {
		return false
	}
	if a.MAC != b.MAC {
		return false
	}
	if a.Hash != b.Hash {
		return false
	}
	if a.KSF != b.KSF {
		return false
	}
	if a.AKE != b.AKE {
		return false
	}

	return bytes.Equal(a.Context, b.Context)
}

// Example_Configuration shows how to instantiate a configuration, which is used to initialize clients and servers from.
// Configurations MUST remain the same for a given client between sessions, or the client won't be able to execute the
// protocol. Configurations can be serialized and deserialized, if you need to save, hardcode, or transmit it.
func Example_configuration() {
	// You can compose your own configuration or choose a recommended default configuration.
	// The two following configuration setups are the same.
	defaultConf := opaque.DefaultConfiguration()

	customConf := &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		KSF:     ksf.Scrypt,
		AKE:     opaque.RistrettoSha512,
		Context: nil,
	}

	if !isSameConf(defaultConf, customConf) {
		// isSameConf() this is just a demo function to check equality.
		log.Fatalln("Oh no! Configurations differ!")
	}

	// A configuration can be saved in an app with this 8-byte array, and decoded at runtime.
	// Any additional 'Context' is also added.
	encoded := defaultConf.Serialize()

	decodedConf, err := opaque.DeserializeConfiguration(encoded)
	if err != nil {
		log.Fatalf("Oh no! Decoding the configurations failed! %v", err)
	}

	if !isSameConf(defaultConf, decodedConf) {
		log.Fatalln("Oh no! Something went wrong in decoding the configuration!")
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}

// Example_ServerSetup shows how to set up the long term values for the OPAQUE server.
// - The secret OPRF seed can be unique for each client or the same for all, but must be
//	 the same for a given client between registration and all login sessions.
// - The AKE key pair can also be the same for all clients or unique, but must be
//	 the same for a given client between registration and all login sessions.
func Example_serverSetup() {
	// This a straightforward way to use a secure and efficient configuration.
	// They have to be run only once in the application's lifecycle, and the output values must be stored appropriately.
	conf := opaque.DefaultConfiguration()
	secretOprfSeed = conf.GenerateOPRFSeed()
	serverPrivateKey, serverPublicKey = conf.KeyGen()

	if serverPrivateKey == nil || serverPublicKey == nil || secretOprfSeed == nil {
		log.Fatalf("Oh no! Something went wrong setting up the server secrets!")
	}

	fmt.Println("OPAQUE server values initialized.")

	// Output: OPAQUE server values initialized.
}

// Example_Registration demonstrates in a single function the interactions between a client and a server for the
// registration phase. This is of course a proof-of-concept demonstration, as client and server execute separately.
// The server outputs a ClientRecord and the credential identifier. The latter is a unique identifier for  a given
// client (e.g. database entry ID), and that must absolutely stay the same for the whole client existence and
// never be reused.
func Example_registration() {
	// The server must have been set up with its long term values once. So we're calling this, here, for the demo.
	{
		Example_serverSetup()
	}

	// Secret client information.
	password := []byte("password")

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("username")
	conf := opaque.DefaultConfiguration()

	// Runtime instantiation for the client and server.
	client, err := conf.Client()
	if err != nil {
		log.Fatalln(err)
	}

	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	// These are the 3 registration messages that will be exchanged.
	// The credential identifier credID is a unique identifier for a given client (e.g. database entry ID), and that
	// must absolutely stay the same for the whole client existence and never be reused.
	var message1, message2, message3 []byte
	var credID []byte

	// The client starts, serializes the message, and sends it to the server.
	{
		c1 := client.RegistrationInit(password)
		message1 = c1.Serialize()
	}

	// The server receives the encoded message, decodes it, interprets it, and returns its response.
	{
		request, err := server.Deserialize.RegistrationRequest(message1)
		if err != nil {
			log.Fatalln(err)
		}

		// The server creates a database entry for the client and creates a credential identifier that must absolutely
		// be unique among all clients.
		credID = opaque.RandomBytes(64)
		pks, err := server.Deserialize.DecodeAkePublicKey(serverPublicKey)
		if err != nil {
			log.Fatalln(err)
		}

		// The server uses its public key and secret OPRF seed created at the setup.
		response := server.RegistrationResponse(request, pks, credID, secretOprfSeed)

		// The server responds with its serialized response.
		message2 = response.Serialize()
	}

	// The client deserializes the responses, and sends back its final client record containing the envelope.
	{
		response, err := client.Deserialize.RegistrationResponse(message2)
		if err != nil {
			log.Fatalln(err)
		}

		// The client produces its record and a client-only-known secret export_key, that the client can use for other purposes (e.g. encrypt
		// information to store on the server, and that the server can't decrypt). We don't use in the example here.
		record, _ := client.RegistrationFinalize(response, clientID, serverID)
		message3 = record.Serialize()
	}

	// Server registers the client record.
	{
		record, err := server.Deserialize.RegistrationRecord(message3)
		if err != nil {
			log.Fatalln(err)
		}

		exampleClientRecord = &opaque.ClientRecord{
			CredentialIdentifier: credID,
			ClientIdentity:       clientID,
			RegistrationRecord:   record,
		}

		fmt.Println("OPAQUE registration is easy!")
	}

	// Output: OPAQUE server values initialized.
	// OPAQUE registration is easy!
}

// Example_LoginKeyExchange demonstrates in a single function the interactions between a client and a server for the
// login phase. This is of course a proof-of-concept demonstration, as client and server execute separately.
func Example_loginKeyExchange() {
	// For the purpose of this demo, we consider the following registration has already happened.
	{
		Example_registration()
	}

	// Secret client information.
	password := []byte("password")

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("username")
	conf := opaque.DefaultConfiguration()

	// Runtime instantiation for the client and server.
	client, err := conf.Client()
	if err != nil {
		log.Fatalln(err)
	}

	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	// These are the 3 login messages that will be exchanged,
	// and the respective sessions keys for the client and server.
	var message1, message2, message3 []byte
	var clientSessionKey, serverSessionKey []byte

	// The client initiates the ball and sends the serialized ke1 to the server.
	{
		ke1 := client.LoginInit(password)
		message1 = ke1.Serialize()
	}

	// The server interprets ke1, and sends back ke2.
	{
		ke1, err := server.Deserialize.KE1(message1)
		if err != nil {
			log.Fatalln(err)
		}

		ke2, err := server.LoginInit(ke1, serverID, serverPrivateKey, serverPublicKey, secretOprfSeed,
			exampleClientRecord)
		if err != nil {
			log.Fatalln(err)
		}

		message2 = ke2.Serialize()
	}

	// The client interprets ke2. If everything went fine, the server is considered trustworthy and the client
	// can use the shared session key and secret export key.
	{
		ke2, err := client.Deserialize.KE2(message2)
		if err != nil {
			log.Fatalln(err)
		}

		// In this example, we don't use the secret export key. The client sends the serialized ke3 to the server.
		ke3, _, err := client.LoginFinish(clientID, serverID, ke2)
		if err != nil {
			log.Fatalln(err)
		}

		message3 = ke3.Serialize()

		// If no error occurred, the server can be trusted, and the client can use the session key.
		clientSessionKey = client.SessionKey()
	}

	// The server must absolutely validate this last message to authenticate the client and continue. If this message
	// does not return successfully, the server must not send any secret or sensitive information and immediately cease
	// the connection.
	{
		ke3, err := server.Deserialize.KE3(message3)
		if err != nil {
			log.Fatalln(err)
		}

		if err := server.LoginFinish(ke3); err != nil {
			log.Fatalln(err)
		}

		// If no error occurred at this point, the server can trust the client and safely extract the shared session key.
		serverSessionKey = server.SessionKey()
	}

	// The following test does not exist in the real world and simply proves the point that the keys match.
	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		log.Fatalln("Oh no! Abort! The shared session keys don't match!")
	}

	fmt.Println("OPAQUE is much awesome!")
	// Output: OPAQUE server values initialized.
	// OPAQUE registration is easy!
	// OPAQUE is much awesome!
}

func Example_deserializer() {
	conf := opaque.DefaultConfiguration()

	conf.
}