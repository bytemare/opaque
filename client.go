package opaque

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Client struct {
	Core *core.Core
	Ake  *ake.Client
	Ke1  *message.KE1
}

func NewClient(suite voprf.Ciphersuite, h hash.Identifier, mode envelope.Mode, m *mhf.Parameters, nonceLen int) *Client {
	return &Client{
		Core: core.NewCore(suite, h, mode, m),
		Ake:  ake.NewClient(suite.Group(), h, nonceLen),
	}
}

func (c *Client) KeyGen() (sk, pk []byte) {
	return ake.KeyGen(c.Ake.Group)
}

func (c *Client) RegistrationStart(password []byte) *message.RegistrationRequest {
	m := c.Core.OprfStart(password)
	return &message.RegistrationRequest{Data: m}
}

func (c *Client) RegistrationFinalize(creds *envelope.Credentials, resp *message.RegistrationResponse) (*message.RegistrationUpload, []byte, error) {
	envU, exportKey, err := c.Core.BuildEnvelope(resp.Data, resp.Pks, creds)
	if err != nil {
		return nil, nil, err
	}

	return &message.RegistrationUpload{
		Envelope: envU,
		Pku:      creds.Pk,
	}, exportKey, nil
}

func (c *Client) AuthenticationStart(password, clientInfo []byte) *message.KE1 {
	m := c.Core.OprfStart(password)
	credReq := &message.CredentialRequest{Data: m}
	c.Ake.Initialize(nil, nil, 32)
	c.Ke1 = c.Ake.Start(clientInfo)
	c.Ke1.CredentialRequest = credReq

	return c.Ke1
}

func (c *Client) AuthenticationFinalize(idu, ids []byte, ke2 *message.KE2) (*message.KE3, []byte, error) {
	secretCreds, exportKey, err := c.Core.RecoverSecret(idu, ids, ke2.Pks, ke2.Data, ke2.Envelope)
	if err != nil {
		return nil, nil, err
	}

	creds := &envelope.Credentials{
		Sk:  secretCreds.Sku,
		Pk:  c.PublicKey(secretCreds.Sku),
		Idu: idu,
		Ids: ids,
	}

	if creds.Idu == nil {
		creds.Idu = creds.Pk
	}
	if creds.Ids == nil {
		creds.Ids = ke2.Pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke3, _, err := c.Ake.Finalize(creds.Idu, creds.Sk, creds.Ids, ke2.Pks, c.Ke1, ke2)
	if err != nil {
		return nil, nil, err
	}

	return ke3, exportKey, nil
}

func (c *Client) PublicKey(sku []byte) []byte {
	return c.Ake.PublicKey(sku)
}

func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
