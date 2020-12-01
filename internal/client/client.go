// Package client implements the client-side protocol of OPAQUE
package client

import (
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

type envelope struct {
	PrivateKey []byte
	ServerPub  []byte
}

// Client implements the Pake interface.
type Client struct {
	// Client
	username, password []byte

	// Session secrets
	sessionKey []byte

	// OPAQUE protocol engine
	oprf *voprf.Client
	*internal.Opaque
}

// New returns a pointer to an initialised Client structure.
func New(username, password []byte, oprf *voprf.Client, opaque *internal.Opaque) *Client {
	return &Client{
		username: username,
		password: password,
		oprf:     oprf,
		Opaque:   opaque,
	}
}

func (c *Client) openEnvelope(rwdu, encrypted []byte) (*envelope, error) {
	e, err := c.Decrypt(rwdu, encrypted)
	if err != nil {
		return nil, err
	}

	env, err := c.Encoding().Decode(e, &envelope{})
	if err != nil {
		return nil, err
	}

	return env.(*envelope), nil
}
