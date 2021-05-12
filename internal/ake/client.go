// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"errors"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidServerMac = errors.New("invalid server mac")

// Client exposes the client's AKE functions and holds its state.
type Client struct {
	esk           group.Scalar
	sessionSecret []byte
	NonceU        []byte // testing: integrated to support testing, to force values.
}

func NewClient() *Client {
	return &Client{}
}

// SetValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func (c *Client) SetValues(cs ciphersuite.Identifier, esk group.Scalar, nonce []byte, nonceLen int) group.Element {
	g := cs.Get(nil)

	s, nonce := setValues(g, esk, nonce, nonceLen)
	if c.esk == nil || (esk != nil && c.esk != s) {
		c.esk = s
	}

	if c.NonceU == nil {
		c.NonceU = nonce
	}

	return g.Base().Mult(c.esk)
}

// Start initiates the 3DH protocol, and returns a KE1 message with clientInfo.
func (c *Client) Start(cs ciphersuite.Identifier, clientInfo []byte) *message.KE1 {
	epk := c.SetValues(cs, nil, nil, 32)

	return &message.KE1{
		NonceU:     c.NonceU,
		ClientInfo: clientInfo,
		EpkU:       internal.SerializePoint(epk, cs),
	}
}

// Finalize verifies and responds to KE3. If the handshake is successful, the session key is stored and this functions
// returns a KE3 message, and the server_info is one was sent.
func (c *Client) Finalize(p *internal.Parameters, idu, clientSecretKey, ids, serverPublicKey []byte,
	ke1 *message.KE1, ke2 *message.KE2) (*message.KE3, []byte, error) {
	st, sessionSecret, err := core3DH(client, p, c.esk, clientSecretKey, ke2.EpkS, serverPublicKey, ke2.EpkS,
		idu, ids, ke2.NonceS, ke2.CredentialResponse.Serialize(), ke2.Einfo, ke1)
	if err != nil {
		return nil, nil, err
	}

	if !p.MAC.Equal(st.serverMac, ke2.Mac) {
		return nil, nil, errAkeInvalidServerMac
	}

	c.sessionSecret = sessionSecret

	return &message.KE3{Mac: st.clientMac}, st.info, nil
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (c *Client) SessionKey() []byte {
	return c.sessionSecret
}
