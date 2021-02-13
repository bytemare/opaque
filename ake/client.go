package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	*Ake
	NonceU []byte // todo: only useful in testing, to force value
}

func NewClient(g ciphersuite.Identifier, h hash.Identifier) *Client {
	return &Client{
		Ake: &Ake{
			Group: g.Get(nil),
			Hash:  h.Get(),
		},
	}
}

// todo: Only useful in testing, to force values
//  Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (c *Client) Initialize(esk group.Scalar, nonce []byte, nonceLen int) {
	nonce = c.Ake.Initialize(esk, nonce, nonceLen)
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

func (c *Client) ikm(sku, epks, pks []byte) ([]byte, error) {
	sk, epk, gpk, err := decodeKeys(c.Group, sku, epks, pks)
	if err != nil {
		return nil, err
	}

	return k3dh(epk, c.Esk, gpk, c.Esk, epk, sk), nil
}

func (c *Client) Finalize(idu, sku, ids, pks []byte, ke1 *message.KE1, ke2 *message.KE2) (*message.KE3, []byte, error) {
	ikm, err := c.ikm(sku, ke2.EpkS, pks)
	if err != nil {
		return nil, nil, err
	}

	keys := deriveKeys(c.Hash, tag3DH, idu, ke1.NonceU, ids, ke2.NonceS, ikm)

	var serverInfo []byte
	if len(ke2.Einfo) != 0 {
		pad := c.Hash.HKDFExpand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	transcript2 := utils.Concatenate(0, ke1.Serialize(), ke2.CredentialResponse.Serialize(), ke2.NonceS, ke2.EpkS, internal.EncodeVector(ke2.Einfo))
	if !c.checkHmac(transcript2, keys.ServerMac, ke2.Mac) {
		return nil, nil, internal.ErrAkeInvalidServerMac
	}

	transcript3 := append(transcript2, ke2.Mac...)
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
