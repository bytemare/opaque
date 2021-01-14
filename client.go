package opaque

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal/client"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Client struct {
	client *client.Client
}

func NewClient(ciphersuite voprf.Ciphersuite, h hash.Identifier, m *mhf.Parameters, k ake.Identifier) *Client {
	return &Client{client.New(ciphersuite, h, m, k)}
}

func (c *Client) AkeKeyGen() (secretKey, publicKey []byte) {
	sk := c.client.Group.NewScalar().Random()
	secretKey = sk.Bytes()
	publicKey = c.client.Group.Base().Mult(sk).Bytes()

	return
}

func (c *Client) RegistrationStart(password []byte) *message.RegistrationRequest {
	m, _ := c.client.OprfStart(password)
	return &message.RegistrationRequest{Data: m}
}

func (c *Client) RegistrationFinalize(sku, pku []byte, creds message.Credentials, resp *message.RegistrationResponse, enc encoding.Encoding) (*message.RegistrationUpload, []byte, error) {
	envU, exportKey, err := c.client.BuildEnvelope(sku, creds, resp, enc)
	if err != nil {
		return nil, nil, err
	}

	return &message.RegistrationUpload{
		Envelope: *envU,
		Pku:      pku,
	}, exportKey, nil
}

func (c *Client) AuthenticationStart(password, info1 []byte, enc encoding.Encoding) (*message.ClientInit, error) {
	credReq, ke1, err := c.client.AuthenticationStart(password, info1, enc)
	if err != nil {
		return nil, err
	}

	return &message.ClientInit{
		Creq:  *credReq,
		KE1:   ke1,
		Info1: info1,
	}, nil
}

func (c *Client) AuthenticationFinalize(creds message.Credentials, resp *message.ServerResponse, enc encoding.Encoding) (*message.ClientFinish, []byte, error) {
	ke3, exportKey, err := c.client.AuthenticationFinalize(creds, resp, enc)
	if err != nil {
		return nil, nil, err
	}

	return &message.ClientFinish{
		KE3: ke3,
	}, exportKey, nil
}

func (c *Client) SessionKey() []byte {
	return c.client.Ake.SessionKey()
}
