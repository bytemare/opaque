// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/message"
)

var (
	exampleClientRecord  *opaque.ClientRecord
	secretGlobalOprfSeed []byte
	serverPrivateKey     *ecc.Scalar
	serverPublicKey      *ecc.Element
)

func isSameConf(a, b *opaque.Configuration) bool {
	if a.OPRF != b.OPRF ||
		a.KDF != b.KDF ||
		a.MAC != b.MAC ||
		a.Hash != b.Hash ||
		!reflect.DeepEqual(a.KSF, b.KSF) ||
		a.AKE != b.AKE {
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
		AKE:     opaque.RistrettoSha512,
		KSF:     ksf.Argon2id,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		Context: nil,
	}

	if !isSameConf(defaultConf, customConf) {
		// isSameConf() this is just a demo function to check equality.
		log.Fatalln("Oh no! Configurations differ!")
	}

	// A configuration can be saved encoded and saved, and later loaded and decoded at runtime.
	// Any additional 'Context' is also included.
	encoded := defaultConf.Serialize()
	fmt.Printf("Encoded Configuration: %s\n", hex.EncodeToString(encoded))

	// This how you decode that configuration.
	conf, err := opaque.DeserializeConfiguration(encoded)
	if err != nil {
		log.Fatalf("Oh no! Decoding the configurations failed! %v", err)
	}

	if !isSameConf(defaultConf, conf) {
		log.Fatalln("Oh no! Something went wrong in decoding the configuration!")
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: Encoded Configuration: 0101010707070000
	// OPAQUE configuration is easy!
}

// Example_ServerSetup shows how to set up the long term values for the OPAQUE server.
// - The secret OPRF seed can be unique for each client or the same for all, but must be
// the same for a given client between registration and all login sessions.
// - The AKE key pair can also be the same for all clients or unique, but must be
// the same for a given client between registration and all login sessions.
func Example_serverSetup() {
	// This a straightforward way to use a secure and efficient configuration.
	// They have to be run only once in the application's lifecycle, and the output values must be stored appropriately.
	serverID := []byte("server-identity")
	conf := opaque.DefaultConfiguration()
	secretGlobalOprfSeed = conf.GenerateOPRFSeed()
	serverPrivateKey, serverPublicKey = conf.KeyGen()

	if serverPrivateKey == nil || serverPublicKey == nil || secretGlobalOprfSeed == nil {
		log.Fatalf("Oh no! Something went wrong setting up the server secrets!")
	}

	// Server setup
	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	skm := &opaque.ServerKeyMaterial{
		Identity:       serverID,
		PrivateKey:     serverPrivateKey,
		OPRFGlobalSeed: secretGlobalOprfSeed,
	}

	if err = server.SetKeyMaterial(skm); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("OPAQUE server initialized.")

	// Output: OPAQUE server initialized.
}

// Example_Deserialization demonstrates a couple of ways to deserialize OPAQUE protocol messages.
// Message interpretation depends on the configuration context it's exchanged in. Hence, we need the corresponding
// configuration. We can then directly deserialize messages from a Configuration or pass them to Client or Server
// instances which can do it as well.
// You must know in advance what message you are expecting, and call the appropriate deserialization function.
func Example_deserialization() {
	// Let's say we have this RegistrationRequest message we received on the wire.
	registrationMessage, _ := hex.DecodeString("9857e1694af550c515e56a9103292ad07a014b020708d3df57ac4b151f58d323")

	// Pick your configuration.
	conf := opaque.DefaultConfiguration()

	// You can directly deserialize and test the message's validity in that configuration by getting a deserializer.
	deserializer, err := conf.Deserializer()
	if err != nil {
		log.Fatalln(err)
	}

	requestD, err := deserializer.RegistrationRequest(registrationMessage)
	if err != nil {
		log.Fatalln(err)
	}

	// Or if you already have a Server instance, you can use that also.
	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	requestS, err := server.Deserialize.RegistrationRequest(registrationMessage)
	if err != nil {
		// The error message will tell us what's wrong.
		log.Fatalln(err)
	}

	// Alternatively, a Client instance can do that as well.
	client, err := conf.Client()
	if err != nil {
		// The error message will tell us what's wrong.
		log.Fatalln(err)
	}

	requestC, err := client.Deserialize.RegistrationRequest(registrationMessage)
	if err != nil {
		// The error message will tell us what's wrong.
		log.Fatalln(err)
	}

	// All these yield the same message. The following is just a test to proof that point.
	{
		if !reflect.DeepEqual(requestD, requestS) ||
			!reflect.DeepEqual(requestD, requestC) ||
			!reflect.DeepEqual(requestS, requestC) {
			log.Fatalf("Unexpected divergent RegistrationMessages:\n\t- %v\n\t- %v\n\t- %v",
				hex.EncodeToString(requestD.Serialize()),
				hex.EncodeToString(requestS.Serialize()),
				hex.EncodeToString(requestC.Serialize()))
		}

		fmt.Println("OPAQUE messages deserialization is easy!")
	}

	// Output: OPAQUE messages deserialization is easy!
}

// Example_Registration demonstrates in a single function the interactions between a client and a server for the
// registration phase. This is of course a proof-of-concept demonstration, as client and server execute separately.
// The server outputs a ClientRecord and the credential identifier. The latter is a unique identifier for  a given
// client (e.g. database entry ID), and that must absolutely stay the same for the whole client existence and
// never be reused.
func Example_registration() {
	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("username")
	conf := opaque.DefaultConfiguration()

	// Secret client information.
	password := []byte("password")

	// Secret server information, this is set up once and for all, and must be the same for a given client.
	// This can be encoded and backed up with the Encode() and Hex() methods, and later recovered.
	secretGlobalOprfSeed = conf.GenerateOPRFSeed()
	serverPrivateKey, serverPublicKey = conf.KeyGen()

	skm := &opaque.ServerKeyMaterial{
		Identity:       serverID,
		PrivateKey:     serverPrivateKey,
		OPRFGlobalSeed: secretGlobalOprfSeed,
	}

	// Runtime instantiation of the server.
	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	if err = server.SetKeyMaterial(skm); err != nil {
		log.Fatalln(err)
	}

	// Runtime instantiation of the client.
	client, err := conf.Client()
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
		c1, err := client.RegistrationInit(password)
		if err != nil {
			log.Fatalln(err)
		}

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

		// The server uses its public key and secret OPRF seed created at the setup.
		response, err := server.RegistrationResponse(request, serverPublicKey.Encode(), credID)
		if err != nil {
			log.Fatalln(err)
		}

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
		record, _, err := client.RegistrationFinalize(response, clientID, serverID)
		if err != nil {
			log.Fatalln(err)
		}

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

	// Output: OPAQUE registration is easy!
}

// Example_LoginKeyExchange demonstrates in a single function the interactions between a client and a server for the
// login phase.
// This is of course a proof-of-concept demonstration, as client and server execute separately.
func Example_loginKeyExchange() {
	// For the purpose of this demo, we consider the following registration has already happened.
	{
		Example_registration()
	}

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("username")
	conf := opaque.DefaultConfiguration()

	// Secret client information.
	password := []byte("password")

	// Secret server information.
	// This can be encoded and backed up with the Encode() and Hex() methods, and later recovered.
	skm := &opaque.ServerKeyMaterial{
		Identity:       serverID,
		PrivateKey:     serverPrivateKey,
		OPRFGlobalSeed: secretGlobalOprfSeed,
	}

	// Runtime instantiation of the server.
	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	if err = server.SetKeyMaterial(skm); err != nil {
		log.Fatalln(err)
	}

	// Runtime instantiation of the client.
	client, err := conf.Client()
	if err != nil {
		log.Fatalln(err)
	}

	// These are the 3 login messages that will be exchanged,
	// and the respective sessions keys for the client and server.
	var message1, message2, message3 []byte
	var clientSessionKey, serverSessionKey []byte

	// The client initiates the ball and sends the serialized ke1 to the server.
	{
		ke1, err := client.GenerateKE1(password)
		if err != nil {
			log.Fatalln(err)
		}

		message1 = ke1.Serialize()
	}

	// The server interprets ke1, and sends back ke2.
	var serverOutput *opaque.ServerOutput
	{
		var (
			ke1 *message.KE1
			ke2 *message.KE2
		)

		ke1, err = server.Deserialize.KE1(message1)
		if err != nil {
			log.Fatalln(err)
		}

		ke2, serverOutput, err = server.GenerateKE2(ke1, exampleClientRecord)
		if err != nil {
			log.Fatalln(err)
		}

		message2 = ke2.Serialize()
	}

	// The client interprets ke2. If everything went fine, the server is considered trustworthy and the client
	// can use the shared session key and secret export key.
	{
		var ke3 *message.KE3
		ke2, err := client.Deserialize.KE2(message2)
		if err != nil {
			log.Fatalln(err)
		}

		// In this example, we don't use the secret export key. The client sends the serialized ke3 to the server.
		ke3, clientSessionKey, _, err = client.GenerateKE3(ke2, clientID, serverID)
		if err != nil {
			log.Fatalln(err)
		}

		message3 = ke3.Serialize()

		// If no error occurred here, the server can be trusted, and the client can use the session key.
		fmt.Println("OPAQUE succeeded from the client perspective, which can now safely use the session key.")
	}

	// The server must absolutely validate this last message to authenticate the client and continue. If this message
	// does not return successfully, the server must not send any secret or sensitive information and immediately cease
	// the connection.
	{
		ke3, err := server.Deserialize.KE3(message3)
		if err != nil {
			log.Fatalln(err)
		}

		if err = server.LoginFinish(ke3, serverOutput.ClientMAC); err != nil {
			log.Fatalln(err)
		}

		// If no error occurred here, the client can be trusted, and the server can use the session key.
		fmt.Println("OPAQUE succeeded from the server perspective, which can now safely use the session key.")

		// If no error occurred at this point, the server can trust the client and safely extract the shared session key.
		serverSessionKey = serverOutput.SessionSecret
	}

	// The following test does not exist in the real world and simply proves the point that the keys match for the demo.
	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		log.Fatalln("Oh no! Abort! The shared session keys don't match!")
	}

	fmt.Println("OPAQUE is much awesome!")
	// Output: OPAQUE registration is easy!
	// OPAQUE succeeded from the client perspective, which can now safely use the session key.
	// OPAQUE succeeded from the server perspective, which can now safely use the session key.
	// OPAQUE is much awesome!
}

// Example_FakeResponse shows how to counter some client enumeration attacks by faking an existing client entry.
// Precompute the fake client record, and return it when no valid record was found.
// Use this with the server's GenerateKE2 function whenever a client wants to retrieve an envelope but a client
// entry does not exist. Failing to do so results in an attacker being able to enumerate users.
func Example_fakeResponse() {
	// The server must have been set up with its long term values once. So we're calling this, here, for the demo.
	{
		Example_serverSetup()
	}

	// Precompute the fake client record, store it, and use it when no valid record was found for the requested client
	// id. The malicious client will purposefully fail, but can't determine the difference with an existing
	// client record. Choose the same configuration as in your app.
	conf := opaque.DefaultConfiguration()
	fakeRecord, err := conf.GetFakeRecord([]byte("id_to_the_fake_client"))
	if err != nil {
		log.Fatalln(err)
	}

	// Runtime instantiation of the server. Note that there's no change to the regular server setup.
	server, err := conf.Server()
	if err != nil {
		log.Fatalln(err)
	}

	skm := &opaque.ServerKeyMaterial{
		PrivateKey:     serverPrivateKey,
		OPRFGlobalSeed: secretGlobalOprfSeed,
	}

	if err = server.SetKeyMaterial(skm); err != nil {
		log.Fatalln(err)
	}

	// Later, during protocol execution, let's say this is the fraudulent login message we received,
	// for which no client entry exists.
	message1, _ := hex.DecodeString("b4d366645e7ae380f9d476e1319e67c1821f7a5d3dfbfc4e26c7898351979139" +
		"0ea528fc609b4393b0353e85fdbb20c6067c11919f40d93d8bb229967fc2878c" +
		"209786ef4b960bfbfe10481c1fd301300fc72dc4234a1e829b556c720f904d30")

	// Continue as usual, using the fake record in lieu of the (non-)existing one. The server the sends
	// back the serialized ke2 message message2.
	var message2 []byte
	{
		ke1, err := server.Deserialize.KE1(message1)
		if err != nil {
			log.Fatalln(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, fakeRecord)
		if err != nil {
			log.Fatalln(err)
		}

		message2 = ke2.Serialize()
	}

	// The following is just a test to check everything went fine.
	{
		if len(message2) == 0 {
			log.Fatalln("Fake KE2 is unexpectedly empty.")
		}

		fmt.Println("Thwarting OPAQUE client enumeration is easy!")
	}

	// Output: OPAQUE server initialized.
	// Thwarting OPAQUE client enumeration is easy!
}
