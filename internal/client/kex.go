// Package client implements the client-side protocol of OPAQUE
package client

import (
	"fmt"

	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/signature"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

func (c *Client) start() ([]byte, error) {
	// Build the OPRF message
	oprf := c.oprfStart()

	// Build the first key exchange message
	c.Kex = ake.SigmaI.Get(pake.Initiator, c.Crypto.Parameters.Group, c.Crypto.Parameters.Hash, nil, c.username, c.Sni)

	_, kex, err := c.Kex.Kex(message.StageStart, nil)
	if err != nil {
		return nil, err
	}

	// Bundle it in a message
	startMessage := message.Start{
		OPRFInit: *oprf,
		Kex:      *kex,
	}

	return startMessage.Encode(c.Encoding())
}

func (c *Client) finish(r *message.Response) ([]byte, error) {
	// Finish the OPRF and derive the secret key
	rwdu, err := c.oprfFinish(&r.OPRFResponse)
	if err != nil {
		return nil, fmt.Errorf("finishing OPRF : %w", err)
	}

	// Open the envelope to get the private key
	// todo : envelope has sensitive key material, and should be cleared from memory just after kex use
	env, err := c.openEnvelope(rwdu, r.Extra)
	if err != nil {
		return nil, fmt.Errorf("opening the sealed envelope : %w", err)
	}

	// todo : this is sensitive key material, and should be cleared from memory just after kex use
	s := signature.New(signature.Ed25519)
	s.LoadKey(env.PrivateKey)

	// Load the own private key and the server's public key into the key exchange engine for signatures
	c.Kex.SetSignature(s)
	c.Kex.SetPeerPublicKey(env.ServerPub)

	//
	sk, kex, err := c.Kex.Kex(message.StageAuth, &r.Kex)
	if err != nil {
		return nil, err
	}

	c.sessionKey = sk

	c.Expect = message.StageTerminated

	return kex.Encode(c.Encoding())
}
