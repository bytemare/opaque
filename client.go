package opaque

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Client struct {
	Core *envelope.Core
	Ake  *ake.Client
}

func NewClient(suite voprf.Ciphersuite, h hash.Identifier, mode envelope.Mode, m *mhf.Parameters, k ake.Identifier, nonceLen int) *Client {
	return &Client{
		Core: envelope.NewCore(suite, h, mode, m),
		Ake:  k.Client(suite.Group(), h, nonceLen),
	}
}

func (c *Client) KeyGen() (sk, pk []byte) {
	return c.Ake.KeyGen()
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

func (c *Client) AuthenticationStart(password, clientInfo []byte) *message.ClientInit {
	m := c.Core.OprfStart(password)
	credReq := &message.CredentialRequest{Data: m}

	c.Ake.Metadata.Init(credReq, clientInfo)

	c.Ake.Initialize(nil, nil)
	ke1 := c.Ake.Start()

	return &message.ClientInit{
		Creq: credReq,
		KE1:  ke1.Serialize(),
	}
}

func (c *Client) AuthenticationFinalize(idu, ids []byte, resp *message.ServerResponse) (*message.ClientFinish, []byte, error) {
	credResp, _, err := message.DeserializeCredentialResponse(resp.Cresp.Serialize(), c.Core.Group.Get(nil).ElementLength(), c.Core.Hash.OutputSize())
	if err != nil {
		return nil, nil, err
	}

	secretCreds, exportKey, err := c.Core.RecoverSecret(idu, ids, credResp.Pks, credResp.Data, credResp.Envelope)
	if err != nil {
		return nil, nil, err
	}

	creds := &envelope.Credentials{
		Sk:  secretCreds.Sku,
		Pk:  c.PublicKey(secretCreds.Sku),
		Idu: idu,
		Ids: ids,
	}

	c.Ake.Metadata.Fill(credResp.Envelope.Contents.Mode, credResp, creds.Pk, credResp.Pks, creds)

	ke3, _, err := c.Ake.Finalize(creds.Sk, credResp.Pks, resp.KE2)
	if err != nil {
		return nil, nil, err
	}

	return &message.ClientFinish{
		KE3: ke3,
	}, exportKey, nil
}

func (c *Client) PublicKey(sku []byte) []byte {
	return c.Ake.PublicKey(sku)
}

func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
