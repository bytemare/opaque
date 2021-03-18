package opaque

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	Core *core.Core
	Ake  *ake.Client
	Ke1  *message.KE1
	*message.Deserializer
}

func NewClient(p *Parameters) *Client {
	k := &internal.KDF{Hash: p.KDF.Get()}
	mac2 := &internal.Mac{Hash: p.MAC.Get()}
	h2 := &internal.Hash{H: p.Hash.Get()}
	mhf2 := &internal.MHF{MHF: p.MHF.Get()}
	return &Client{
		Core:         core.NewCore(p.OprfCiphersuite, k, mac2, mhf2, p.Mode, p.Group),
		Ake:          ake.NewClient(p.Group, k, mac2, h2),
		Deserializer: p.Deserializer(),
	}
}

func (c *Client) KeyGen() (sk, pk []byte) {
	return ake.KeyGen(c.Ake.Identifier)
}

func (c *Client) RegistrationStart(password []byte) *message.RegistrationRequest {
	m := c.Core.OprfStart(password)
	return &message.RegistrationRequest{Data: internal.PadPoint(m, c.Core.Group)}
}

func (c *Client) RegistrationFinalize(creds *envelope.Credentials, resp *message.RegistrationResponse) (*message.RegistrationUpload, []byte, error) {
	envU, pkc, exportKey, err := c.Core.BuildEnvelope(resp.Data, resp.Pks, creds)
	if err != nil {
		return nil, nil, err
	}

	if creds.Nonce == nil {
		creds.Nonce = utils.RandomBytes(32)
	}

	return &message.RegistrationUpload{
		Envelope: envU,
		Pku:      pkc,
	}, exportKey, nil
}

func (c *Client) AuthenticationStart(password, clientInfo []byte) *message.KE1 {
	m := c.Core.OprfStart(password)
	credReq := &message.CredentialRequest{Data: internal.PadPoint(m, c.Core.Group)}
	c.Ke1 = c.Ake.Start(clientInfo)
	c.Ke1.CredentialRequest = credReq

	return c.Ke1
}

func (c *Client) publicKey(skc []byte) ([]byte, error) {
	sk, err := c.Ake.Group.NewScalar().Decode(skc)
	if err != nil {
		return nil, err
	}

	return c.Ake.Group.Base().Mult(sk).Bytes(), nil
}

func (c *Client) AuthenticationFinalize(idu, ids []byte, ke2 *message.KE2) (*message.KE3, []byte, error) {
	secretCreds, exportKey, err := c.Core.RecoverSecret(idu, ids, ke2.Pkc, ke2.Pks, ke2.Data, ke2.Envelope)
	if err != nil {
		return nil, nil, err
	}

	creds := &envelope.Credentials{
		Skx: secretCreds.Skc,
		Pkc: ke2.Pkc,
		Idc: idu,
		Ids: ids,
	}

	if creds.Idc == nil {
		creds.Idc = creds.Pkc
	}

	if creds.Ids == nil {
		creds.Ids = ke2.Pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke3, _, err := c.Ake.Finalize(creds.Idc, creds.Skx, creds.Ids, ke2.Pks, c.Ke1, ke2)
	if err != nil {
		return nil, nil, err
	}

	return ke3, exportKey, nil
}

func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
