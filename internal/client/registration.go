// Package client implements the client-side protocol of OPAQUE
package client

import (
	"fmt"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/signature"

	"github.com/bytemare/pake/message"
)

func (c *Client) makeEnvelope(serverPublicKey []byte) (encoded, publicKey []byte, err error) {
	// Generate a fresh private key
	s := signature.New(signature.Ed25519)
	if err := s.GenerateKey(); err != nil {
		return nil, nil, err
	}

	// todo : envelope has sensitive key material, and should be cleared from memory just after kex use
	env := envelope{
		PrivateKey: s.GetPrivateKey(),
		ServerPub:  serverPublicKey,
	}

	encoded, err = c.Encoding().Encode(&env)

	return encoded, s.GetPublicKey(), err
}

func (c *Client) sealEnvelope(rwdu, env []byte) []byte {
	return c.Encrypt(rwdu, env)
}

func (c *Client) registerFinish(p *message.OPRFResponse) ([]byte, error) {
	rwdu, err := c.oprfFinish(p)
	if err != nil {
		return nil, fmt.Errorf("finishing OPRF : %w", err)
	}

	// todo : envelope has sensitive key material, and should be cleared from memory just after kex use
	envelope, publicKey, err := c.makeEnvelope(p.Extra)
	if err != nil {
		return nil, err
	}

	// todo  Add assertion for rwdu length :
	//  16, 24, or 32 bytes to select AES-128, AES-192, or AES-256

	encrypted := c.sealEnvelope(rwdu, envelope)

	// todo : here rwdu can be wiped

	verifier := internal.RegistrationPayload{
		PublicKey: publicKey,
		Envelope:  encrypted,
	}

	v, err := verifier.Encode(c.Encoding())
	if err != nil {
		return nil, err
	}

	reg := message.Registration{Verifier: v}

	c.Expect = message.StageTerminated

	return reg.Encode(c.Encoding())
}
