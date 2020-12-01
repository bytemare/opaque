// Package client implements the client-side protocol of OPAQUE
package client

import (
	"errors"

	"github.com/bytemare/cryptotools"

	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

// SetUserRecord is only used by the server to load the input record matching the client to authenticate.
func (c *Client) SetUserRecord(_ interface{}) error {
	return errors.New("can't call SetUserRecord in client role")
}

// Register needs to be called consecutively for the registration steps, and returns a message to send to the peer.
//
// Calling Register() with nil, indicates starting the registration process.
// Calling Register() with the server response will finish the process and return the final message to send to the server.
func (c *Client) Register(m []byte) ([]byte, error) {
	return c.handle(m)
}

// Authenticate is to be called successively throughout the whole OPAQUE process with the received message.
// The response, if any, should be send to the peer.
//
// The first call should be with nil as argument, and all subsequent calls should be the server responses to previous messages.
func (c *Client) Authenticate(m []byte) ([]byte, error) {
	return c.handle(m)
}

// SessionKey returns the OPAQUE shared session key, if and only if all Authenticate() steps have succeeded.
func (c *Client) SessionKey() []byte {
	return c.sessionKey
}

// EncodedParameters returns the 4-byte encoding of the ciphersuite parameters.
func (c *Client) EncodedParameters() cryptotools.CiphersuiteEncoding {
	return c.Crypto.Parameters.Encode()
}

func (c *Client) handle(m []byte) ([]byte, error) {
	if c.Expect == message.StageTerminated {
		return nil, errors.New("the procedure should have been terminated")
	}

	if m == nil {
		return c.startOPAQUE()
	}

	// Validate the message header and decode the payload
	// payload, err := pake.DecodeMessage(c.Mode(), c.Expect, m, c.Encoding())
	payload, err := c.Expect.Decode(m, c.Encoding())
	if err != nil {
		return nil, err
	}

	switch c.Mode() {
	case pake.Registration:
		// This is the server's OPRF answer
		return c.registerFinish(payload.(*message.OPRFResponse))

	case pake.KeyExchange:
		// Here, we have the server response containing the OPRF and Key Exchange information
		return c.finish(payload.(*message.Response))
	}

	panic("invalid mode")
}

func (c *Client) startOPAQUE() ([]byte, error) {
	switch c.Mode() {
	case pake.Registration:
		return c.oprfStart().Encode(c.Encoding())

	case pake.KeyExchange:
		return c.start()
	}

	panic("invalid mode")
}
