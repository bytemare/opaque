package opaque

import (
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Client struct {
	Core *core.Core
	Ake  *ake.Client
	Ke1  *message.KE1
}

func NewClient(suite voprf.Ciphersuite, kdf, mac, h hash.Hashing, m mhf.Identifier, mode envelope.Mode, akeGroup ciphersuite.Identifier) *Client {
	g := akeGroup.Get(nil)
	k := &internal.KDF{Hash: kdf.Get()}
	mac2 := &internal.Mac{Hash: mac.Get()}
	h2 := &internal.Hash{H: h.Get()}
	mhf2 := &internal.MHF{MHF: m.Get()}
	return &Client{
		Core: core.NewCore(suite, k, mac2, mhf2, mode, g),
		Ake:  ake.NewClient(g, k, mac2, h2),
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
	credReq := &message.CredentialRequest{Data: m}
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
