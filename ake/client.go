package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	*Ake
	*Metadata
}

// Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (c *Client) Initialize(scalar group.Scalar, nonce []byte) {
	nonce = c.Ake.Initialize(scalar, nonce)
	if c.NonceU == nil {
		c.NonceU = nonce
	}
}

func (c *Client) Start() *message.KE1 {
	c.Initialize(nil, nil)
	return &message.KE1{
		NonceU:     c.NonceU,
		ClientInfo: c.Metadata.ClientInfo,
		EpkU:       c.Epk.Bytes(),
	}
}

func (c *Client) Finalize(sku, pks []byte, ke2 *message.KE2) (*message.KE3, []byte, error) {
	ikm, err := clientK3dh(c.Group, c.Esk, sku, ke2.EpkS, pks)
	if err != nil {
		return nil, nil, err
	}

	c.DeriveKeys(c.Metadata, tag3DH, c.NonceU, ke2.NonceS, ikm)

	var serverInfo []byte
	if len(ke2.Einfo) != 0 {
		pad := c.Hash.HKDFExpand(c.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	c.Transcript2 = utils.Concatenate(0, c.Metadata.CredentialRequest, c.NonceU, internal.EncodeVector(c.Metadata.ClientInfo), c.Epk.Bytes(), c.Metadata.CredentialResponse, ke2.NonceS, ke2.EpkS, internal.EncodeVector(ke2.Einfo))
	ht := c.Hash.Hash(0, c.Transcript2)
	if !c.checkHmac(ht, c.ServerMac, ke2.Mac) {
		return nil, nil, internal.ErrAkeInvalidServerMac
	}

	c.Transcript3 = c.Hash.Hash(0, utils.Concatenate(0, c.Transcript2, ke2.Mac))

	return &message.KE3{Mac: c.Hmac(c.Transcript3, c.ClientMac)}, serverInfo, nil
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

func clientK3dh(g group.Group, esk group.Scalar, sku, epks, pks []byte) ([]byte, error) {
	sk, err := g.NewScalar().Decode(sku)
	if err != nil {
		return nil, err
	}

	epk, err := g.NewElement().Decode(epks)
	if err != nil {
		return nil, err
	}

	gpk, err := g.NewElement().Decode(pks)
	if err != nil {
		return nil, err
	}

	e1 := epk.Mult(esk)
	e2 := gpk.Mult(esk)
	e3 := epk.Mult(sk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes()), nil
}
