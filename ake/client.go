package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	*Ake
}

// Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (c *Client) Initialize(scalar group.Scalar, nonce []byte, nonceLen int) {
	nonce = c.Ake.Initialize(scalar, nonce, nonceLen)
	if c.NonceU == nil {
		c.NonceU = nonce
	}
}

func (c *Client) Start(clientInfo []byte) *message.KE1 {
	return &message.KE1{
		NonceU:     c.NonceU,
		ClientInfo: clientInfo,
		EpkU:       c.Epk.Bytes(),
	}
}

func (c *Client) Finalize(idu, sku, ids, pks []byte, ke1 *message.KE1, ke2 *message.KE2) (*message.KE3, []byte, error) {
	ikm, err := c.k3dh(sku, ke2.EpkS, pks)
	if err != nil {
		return nil, nil, err
	}

	keys := DeriveKeys(c.Hash, tag3DH, idu, ke1.NonceU, ids, ke2.NonceS, ikm)

	var serverInfo []byte
	if len(ke2.Einfo) != 0 {
		pad := c.Hash.HKDFExpand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	transcript2 := utils.Concatenate(0, ke1.CredentialRequest.Serialize(), ke1.NonceU, internal.EncodeVector(ke1.ClientInfo), c.Epk.Bytes(), ke2.CredentialResponse.Serialize(), ke2.NonceS, ke2.EpkS, internal.EncodeVector(ke2.Einfo))
	ht := c.Hash.Hash(0, transcript2)
	if !c.checkHmac(ht, keys.ServerMac, ke2.Mac) {
		return nil, nil, internal.ErrAkeInvalidServerMac
	}

	transcript3 := c.Hash.Hash(0, append(transcript2, ke2.Mac...))
	c.Keys = keys
	c.SessionSecret = keys.SessionSecret

	return &message.KE3{Mac: c.Hmac(transcript3, keys.ClientMac)}, serverInfo, nil
}

func (c *Client) PublicKey(sku []byte) []byte {
	sk, err := c.Ake.Group.NewScalar().Decode(sku)
	if err != nil {
		panic(err)
	}

	return c.Ake.Group.Base().Mult(sk).Bytes()
}

func (c *Client) SessionKey() []byte {
	return c.SessionSecret
}

func (c *Client) k3dh(sku, epks, pks []byte) ([]byte, error) {
	sk, err := c.Group.NewScalar().Decode(sku)
	if err != nil {
		return nil, err
	}

	epk, err := c.Group.NewElement().Decode(epks)
	if err != nil {
		return nil, err
	}

	gpk, err := c.Group.NewElement().Decode(pks)
	if err != nil {
		return nil, err
	}

	e1 := epk.Mult(c.Esk)
	e2 := gpk.Mult(c.Esk)
	e3 := epk.Mult(sk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes()), nil
}
