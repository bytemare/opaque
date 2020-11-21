package opaque

/**
This OPAQUE implementation's peers communicate with []byte encoded messages, that can be simply transmitted.
*/

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/record"
)

// The user record to be used for registration and authentication
var rec *record.UserRecord

func newServerPrivateKey() []byte {
	_, s, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	return s.Seed()
}

func ExampleOPAQUERegistration() {
	serverID := []byte("server")
	username := []byte("user")
	password := []byte("password")

	clientParams := &Parameters{
		SNI:      serverID,
		UserID:   username,
		Secret:   password,
		Encoding: encoding.JSON,
	}

	/*
		A client wants to play OPAQUE with the server, identified by sni, and wants to register
	*/
	client, err := Registration.Client(clientParams, nil)
	if err != nil {
		panic(err)
	}

	/*
		Let's say the server receives the first message, reads the username from the request,
		and fetches the database entry for the user.

		In this Example, we're just going to create a dummy user record.

		It is supposed the server disposes of a pair of private and public keys, used for the database.
	*/
	privateKey := newServerPrivateKey()
	csp, err := cryptotools.ReadCiphersuite(client.EncodedParameters())
	if err != nil {
		panic(err)
	}
	rec, err = record.NewUserRecord(username, privateKey, csp)
	if err != nil {
		panic(err)
	}

	//
	serverParams := &Parameters{
		SNI:      serverID,
		Encoding: encoding.JSON,
	}

	server, err := Registration.Server(serverParams, nil)
	if err != nil {
		panic(err)
	}

	// And now we load the user record
	if err := server.SetUserRecord(rec); err != nil {
		panic(err)
	}

	/*
		Let's register a new envelope to the server. The client generates the first message, and sends it to the server.
	*/
	message1, err := client.Register(nil)
	if err != nil {
		panic(err)
	}

	/*
		The server sends back the client record
	*/
	message2, err := server.Register(message1)
	if err != nil {
		panic(err)
	}

	/*
		The setup is complete, we can proceed to the key exchange
	*/
	message3, err := client.Register(message2)
	if err != nil {
		panic(err)
	}

	/*
		The server updates the client entry with the new envelope
	*/
	_, err = server.Register(message3)
	if err != nil {
		panic(err)
	}

	/*
		The client has now its sealed enveloped stored on the server
	*/
	if rec.Envelope != nil {
		fmt.Println("An envelope was registered on the server.")
	} else {
		fmt.Println("Warning: no envelope was registered but no error has been raised before.")
	}
	// Output: An envelope was registered on the server.
}

func ExampleOPAQUEAuthentication() {
	serverID := []byte("server")
	username := []byte("user")
	password := []byte("password")

	// Suppose a client record was setup earlier and stored in a database
	ExampleOPAQUERegistration()

	/*
		let's say the client wants to authenticate to the server, using the stored envelope
	*/
	clientParams := &Parameters{
		SNI:    serverID,
		UserID: username,
		Secret: password,
	}
	client, err := Authentication.Client(clientParams, nil)
	if err != nil {
		panic(err)
	}

	message1, err := client.Authenticate(nil)
	if err != nil {
		panic(err)
	}

	/*
		The server answers
	*/
	serverParams := &Parameters{
		SNI: serverID,
	}
	server, err := Authentication.Client(serverParams, nil)
	if err != nil {
		panic(err)
	}

	// And now we load the user record
	server.SetUserRecord(rec)

	message2, err := server.Authenticate(message1)
	if err != nil {
		panic(err)
	}

	/*
		The client receives the server's answer and will have the session key, but needs to explicitly authenticate to the
		server. We therefore send the last message.
	*/
	message3, err := client.Authenticate(message2)
	if err != nil {
		panic(err)
	}

	clientSessionKey := client.SessionKey()

	/*
		The server absolutely MUST verify the client's authenticity before continuing or encrypting anything else.
		This call will only return a nil message, since message3 is the last message of the key exchange.
	*/
	_, err = server.Authenticate(message3)
	if err != nil {
		panic(err)
	}

	serverSessionKey := server.SessionKey()

	/*
		At this point, both client and server share the same session key
	*/
	if bytes.Equal(clientSessionKey, serverSessionKey) {
		fmt.Println("Both parties share the same secret session key")
	} else {
		fmt.Println("Something went wrong, and should have been detected before.")
	}

	// Output: An envelope was registered on the server.
	// Both parties share the same secret session key
}
