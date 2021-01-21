package opaque

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

const (
	opaqueInfo = "OPAQUE01"
)

type Client struct {
	oprf *voprf.Client
	Core *envelope.Core
	Ake  *ake.Client
}

func NewClient(suite voprf.Ciphersuite, h hash.Identifier, mode envelope.Mode, m *mhf.Parameters, k ake.Identifier, g ciphersuite.Identifier, nonceLen int) *Client {
	oprf, err := suite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Client{
		oprf: oprf,
		Core: envelope.NewCore(h, mode, m),
		Ake:  k.Client(g, h, nonceLen),
	}
}

func (c *Client) KeyGen() (sk, pk []byte) {
	return c.Ake.KeyGen()
}

func (c *Client) RegistrationStart(password []byte) *message.RegistrationRequest {
	m := c.oprf.Blind(password)
	return &message.RegistrationRequest{Data: m}
}

func (c *Client) oprfFinish(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.oprf.Finalize(ev, []byte(opaqueInfo))
}

func (c *Client) RegistrationFinalize(creds *envelope.Credentials, resp *message.RegistrationResponse, enc encoding.Encoding) (*message.RegistrationUpload, []byte, error) {
	unblinded, err := c.oprfFinish(resp.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	envU, exportKey, err := c.Core.BuildEnvelope(unblinded, resp.Pks, creds, enc)
	if err != nil {
		return nil, nil, err
	}

	return &message.RegistrationUpload{
		Envelope: *envU,
		Pku:      creds.Pk,
	}, exportKey, nil
}

func (c *Client) AuthenticationStart(password, info1 []byte, enc encoding.Encoding) (*message.ClientInit, error) {
	m := c.oprf.Blind(password)
	credReq := &message.CredentialRequest{Data: m}

	if err := c.Ake.Metadata.Init(credReq, info1, enc); err != nil {
		return nil, err
	}

	ke1 := c.Ake.Start()

	return &message.ClientInit{
		Creq:  *credReq,
		KE1:   ke1.Encode(enc),
		Info1: info1,
	}, nil
}

func (c *Client) RecoverCredentials(idu, ids []byte, resp *message.ServerResponse, enc encoding.Encoding) (*envelope.SecretCredentials, []byte, error) {
	unblinded, err := c.oprfFinish(resp.Cresp.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	return c.Core.RecoverSecret(idu, ids, resp.Cresp.Pks, unblinded, &resp.Cresp.Envelope, enc)
}

func (c *Client) AuthenticationFinalize(idu, ids []byte, resp *message.ServerResponse, enc encoding.Encoding) (*message.ClientFinish, []byte, error) {
	secretCreds, exportKey, err := c.RecoverCredentials(idu, ids, resp, enc)
	if err != nil {
		return nil, nil, err
	}

	creds := &envelope.Credentials{
		Sk:  secretCreds.Sku,
		Pk:  c.PublicKey(secretCreds.Sku),
		Idu: idu,
		Ids: ids,
	}

	if err := c.Ake.Metadata.Fill(resp.Cresp.Envelope.Contents.Mode, &resp.Cresp, creds.Pk, resp.Cresp.Pks, creds, enc); err != nil {
		return nil, nil, err
	}

	ke3, err := c.Ake.Finalize(creds.Sk, resp.Cresp.Pks, resp.KE2, resp.EInfo2, enc)
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
