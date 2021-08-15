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

	"github.com/bytemare/crypto/mhf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
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
	if a.MHF != b.MHF {
		return false
	}
	if a.Mode != b.Mode {
		return false
	}
	if a.AKE != b.AKE {
		return false
	}

	return bytes.Equal(a.Context, b.Context)
}

func ExampleConfiguration() {
	// Note that applications must use the same configuration throughout their lifecycle, and be the same on both client
	// and server. The two following configurations are the same, and are recommended.

	defaultConf := opaque.DefaultConfiguration()

	customConf := &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		MHF:     mhf.Scrypt,
		Mode:    opaque.Internal,
		AKE:     opaque.RistrettoSha512,
		Context: nil,
	}

	if !isSameConf(defaultConf, customConf) {
		log.Fatalln("Oh no! Configurations differ!")
	}

	// A configuration can be hardcoded in an app with this 8-byte array, and decoded at runtime.
	encoded := defaultConf.Serialize()

	conf, err := opaque.DeserializeConfiguration(encoded)
	if err != nil {
		log.Fatalf("Oh no! Decoding the configurations failed! %v", err)
	}

	if !isSameConf(defaultConf, conf) {
		log.Fatalln("Oh no! Something went wrong in decoding the configuration!")
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}

func ExampleClient() {
	// First, load or instantiate a configuration.
	conf := opaque.DefaultConfiguration()

	client := conf.Client()

	if client == nil {
		log.Fatalln("Oh no! Something went wrong setting up the client!")
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}

func ExampleServer() {
	// First, load or instantiate a configuration.
	conf := opaque.DefaultConfiguration()

	server := conf.Server()

	if server == nil {
		log.Fatalln("Oh no! Something went wrong setting up the server!")
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}

var (
	exampleClientRecord                               *opaque.ClientRecord
	secretOprfSeed, serverPrivateKey, serverPublicKey []byte
)

func ExampleRegistration() {
	// We assume the server is already set up with the following values. secret* values are internal secret to the server.
	// They can be unique for all clients, and must be the same for a client between registration and login. It's safe
	// to use these same values across clients as long as they remain secret.
	secretOprfSeed = internal.RandomBytes(32)
	serverPrivateKey, serverPublicKey = opaque.DefaultConfiguration().Server().KeyGen()

	// Secret client information.
	password := []byte("password")

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("client")
	conf := opaque.DefaultConfiguration()

	// Runtime setup
	client := conf.Client()
	server := conf.Server()

	// Client starts, serializes the message, and sends it to the server.
	c1 := client.RegistrationInit(password)
	c1s := c1.Serialize()

	// The server receives the encoded message, decodes it, interprets it, and returns its response.
	s1, err := server.DeserializeRegistrationRequest(c1s)
	if err != nil {
		panic(err)
	}

	// clientID must absolutely be unique among all clients.
	credID := internal.RandomBytes(64)
	s2, err := server.RegistrationResponse(s1, serverPublicKey, credID, secretOprfSeed)
	if err != nil {
		panic(err)
	}

	// The server responds with its serialized response.
	s2s := s2.Serialize()

	// The client deserializes the responses, and sends back its final client record containing the envelope.
	c2, err := client.DeserializeRegistrationResponse(s2s)
	if err != nil {
		panic(err)
	}

	clientCreds := &opaque.Credentials{
		Client: clientID,
		Server: serverID,
	}

	// We're using the internal mode, so we don't have to provide a private key here.
	// This also spits out a client-only secret export_key, that the client can use for other purposes (e.g. encrypt
	// information to store on the server, and that the server can't decrypt). We don't use in the example here.
	c3, _, err := client.RegistrationFinalize(nil, clientCreds, c2)
	if err != nil {
		panic(err)
	}

	c3s := c3.Serialize()

	// Server registers the client upload
	upload, err := server.DeserializeRegistrationRecord(c3s)
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

	// Output: OPAQUE registration is easy!
}

func ExampleLoginKeyExchange() {
	// For the purpose of this demo, we consider the following registration has already happened.
	ExampleRegistration()

	// Secret client information.
	password := []byte("password")

	// Information shared by both client and server.
	serverID := []byte("server")
	clientID := []byte("client")
	conf := opaque.DefaultConfiguration()

	// Run time setup
	client := conf.Client()
	server := conf.Server()

	// The client initiates the ball and sends the serialized ke1 to the server
	ke1 := client.Init(password)
	message1 := ke1.Serialize()

	// The server interprets ke1, and sends back ke2
	ke1s, err := server.DeserializeKE1(message1)
	if err != nil {
		panic(err)
	}

	ke2, err := server.Init(ke1s, serverID, serverPrivateKey, serverPublicKey, secretOprfSeed,
		exampleClientRecord)
	if err != nil {
		panic(err)
	}

	message2 := ke2.Serialize()

	// The client interprets ke2. If the everything went fine, the server is considered trustworthy and the client
	// can use the shared session key and secret export key.
	ke2c, err := client.DeserializeKE2(message2)
	if err != nil {
		panic(err)
	}

	// In this example, we don't use the secret export key. The client sends the serialized ke3 to the server.
	ke3, _, err := client.Finish(clientID, serverID, ke2c)
	if err != nil {
		panic(err)
	}

	clientSessionKey := client.SessionKey()
	if clientSessionKey == nil {
		log.Fatalln("Oh no! Something went wrong!")
	}

	message3 := ke3.Serialize()

	// The server must absolutely validate this last message to authenticate the client and continue. If this message
	// does not return successfully, the server must not send any secret or sensitive information and immediately cease
	// the connection.
	ke3s, err := server.DeserializeKE3(message3)
	if err != nil {
		panic(err)
	}

	if err := server.Finish(ke3s); err != nil {
		panic(err)
	}

	// If server.Finish() returns successfully, we can trust the client and safely extract the shared session key.
	serverSessionKey := server.SessionKey()

	// The following test does not exist in the real world and simply proves the point that the keys match.
	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		log.Fatalln("Oh no! Abort! The shared session keys don't match!")
	}

	fmt.Println("OPAQUE is much awesome!")
	// Output: OPAQUE registration is easy!
	// OPAQUE is much awesome!
}
