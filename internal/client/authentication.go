package client

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/message"
)

func (c *Client) AuthenticationStart(password, info1 []byte, enc encoding.Encoding) (*message.CredentialRequest, []byte, error) {
	m, _ := c.OprfStart(password)

	credReq := &message.CredentialRequest{Data: m}

	if err := c.initMetadata(credReq, info1, enc); err != nil {
		return nil, nil, err
	}

	ke1 := c.Ake.Start(c.nonceLen, enc)

	return credReq, ke1, nil
}

func (c *Client) AuthenticationFinalize(creds message.Credentials, resp *message.ServerResponse, enc encoding.Encoding) (ke3, exportKey []byte, err error) {
	secretCreds, exportKey, err := c.recoverCredentials(creds, &resp.Cresp, enc)
	if err != nil {
		return nil, nil, err
	}

	c.fillMetaData(creds, resp, secretCreds.Sku, enc)

	ke3, err = c.Ake.Finalize(c.meta, secretCreds.Sku, creds.ServerPublicKey(), resp.KE2, resp.EInfo2, enc)
	if err != nil {
		return nil, nil, err
	}

	return ke3, exportKey, nil
}
