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
	"fmt"
	"log"

	"github.com/bytemare/opaque"
)

var (
	exampleClientRecord                               *opaque.ClientRecord
	secretOprfSeed, serverPrivateKey, serverPublicKey []byte
)

// Example_registration demonstrates in a single function the interactions between a client and a server for the
// registration phase. This is of course a proof-of-concept demonstration, as client and server execute separately.
func Example_registration() {
	// The server uses a secret global OPRF seed that can be unique for each client or the same for all, but must be
	// the same for a given client between registration and  all login sessions.
	conf := opaque.DefaultConfiguration()
	secretOprfSeed = conf.GenerateOPRFSeed()
	serverPrivateKey, serverPublicKey = conf.KeyGen()

	// Secret client information.
	password := []byte("password")

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("client")
	conf = opaque.DefaultConfiguration()

	// Runtime setup
	client, err := conf.Client()
	if err != nil {
		panic(err)
	}

	server, err := conf.Server()
	if err != nil {
		panic(err)
	}

	// Messages and output client credential identifier
	var message1, message2, message3 []byte
	var credID []byte

	// Client starts, serializes the message, and sends it to the server.
	{
		c1 := client.RegistrationInit(password)
		message1 = c1.Serialize()
	}

	// The server receives the encoded message, decodes it, interprets it, and returns its response.
	{
		s1, err := server.Deserialize.RegistrationRequest(message1)
		if err != nil {
			panic(err)
		}

		// The server creates a database entry for the client and creates a credential identifier that must absolutely
		// be unique among all clients.
		credID = opaque.RandomBytes(64)
		pks, err := server.Deserialize.DecodeAkePublicKey(serverPublicKey)
		if err != nil {
			panic(err)
		}

		s2 := server.RegistrationResponse(s1, pks, credID, secretOprfSeed)

		// The server responds with its serialized response.
		message2 = s2.Serialize()
	}

	// The client deserializes the responses, and sends back its final client record containing the envelope.
	{
		c2, err := client.Deserialize.RegistrationResponse(message2)
		if err != nil {
			panic(err)
		}

		// This also generates a client-only secret export_key, that the client can use for other purposes (e.g. encrypt
		// information to store on the server, and that the server can't decrypt). We don't use in the example here.
		c3, _ := client.RegistrationFinalize(c2, clientID, serverID)
		message3 = c3.Serialize()
	}

	// Server registers the client record.
	{
		upload, err := server.Deserialize.RegistrationRecord(message3)
		if err != nil {
			panic(err)
		}

		exampleClientRecord = &opaque.ClientRecord{
			CredentialIdentifier: credID,
			ClientIdentity:       clientID,
			RegistrationRecord:   upload,
		}

		if exampleClientRecord.RegistrationRecord != nil {
			fmt.Println("OPAQUE registration is easy!")
		} else {
			log.Fatalln("Oh no! Something went wrong storing the client record.")
		}
	}

	// Output: OPAQUE registration is easy!
}

// Example_loginKeyExchange demonstrates in a single function the interactions between a client and a server for the
// login phase. This is of course a proof-of-concept demonstration, as client and server execute separately.
func Example_loginKeyExchange() {
	// For the purpose of this demo, we consider the following registration has already happened.
	Example_registration()

	// Secret client information.
	password := []byte("password")

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("client")
	conf := opaque.DefaultConfiguration()

	// Run time setup
	client, err := conf.Client()
	if err != nil {
		panic(err)
	}

	server, err := conf.Server()
	if err != nil {
		panic(err)
	}

	// Messages and output values
	var message1, message2, message3 []byte
	var clientSessionKey, serverSessionKey []byte

	// The client initiates the ball and sends the serialized ke1 to the server.
	{
		ke1 := client.LoginInit(password)
		message1 = ke1.Serialize()
	}

	// The server interprets ke1, and sends back ke2.
	{
		ke1s, err := server.Deserialize.KE1(message1)
		if err != nil {
			panic(err)
		}

		ke2, err := server.LoginInit(ke1s, serverID, serverPrivateKey, serverPublicKey, secretOprfSeed,
			exampleClientRecord)
		if err != nil {
			panic(err)
		}

		message2 = ke2.Serialize()
	}

	// The client interprets ke2. If everything went fine, the server is considered trustworthy and the client
	// can use the shared session key and secret export key.
	{
		ke2c, err := client.Deserialize.KE2(message2)
		if err != nil {
			panic(err)
		}

		// In this example, we don't use the secret export key. The client sends the serialized ke3 to the server.
		ke3, _, err := client.LoginFinish(clientID, serverID, ke2c)
		if err != nil {
			panic(err)
		}

		message3 = ke3.Serialize()

		// If no error occurred, the server can be trusted, and the client can use the session key.
		clientSessionKey = client.SessionKey()
	}

	// The server must absolutely validate this last message to authenticate the client and continue. If this message
	// does not return successfully, the server must not send any secret or sensitive information and immediately cease
	// the connection.
	{
		ke3s, err := server.Deserialize.KE3(message3)
		if err != nil {
			panic(err)
		}

		if err := server.LoginFinish(ke3s); err != nil {
			panic(err)
		}

		// If no error occurred, the server can trust the client and safely extract the shared session key.
		serverSessionKey = server.SessionKey()
	}

	// The following test does not exist in the real world and simply proves the point that the keys match.
	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		log.Fatalln("Oh no! Abort! The shared session keys don't match!")
	}

	fmt.Println("OPAQUE is much awesome!")
	// Output: OPAQUE registration is easy!
	// OPAQUE is much awesome!
}
