package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/sigmai"
	"github.com/bytemare/opaque/internal"
)

type Client struct {
	id Identifier
	*Metadata
	*Ake
}

func (c *Client) Identifier() Identifier {
	return c.id
}

// Note := there's no effect if esk, epk, and nonce have already been set
func (c *Client) Initialize(scalar group.Scalar, nonce []byte) {
	nonce = c.Ake.Initialize(scalar, nonce)
	if c.NonceU == nil {
		c.NonceU = nonce
	}
}

func (c *Client) Start() *Ke1 {
	c.Initialize(nil, nil)
	return &Ke1{
		NonceU: c.NonceU,
		ClientInfo: c.Metadata.ClientInfo,
		EpkU:   c.Epk.Bytes(),
	}
}

func (c *Client) Finalize(sku, pks, message []byte) ([]byte, []byte, error) {
	ke2, err := DeserializeKe2(message, c.NonceLen, c.Group.ElementLength(), c.Hash.OutputSize())
	if err != nil {
		return nil, nil, err
	}

	nonceS := ke2.NonceS

	ikm, err := clientK3dh(c.Group, c.Esk, sku, ke2.EpkS, pks)
	if err != nil {
		return nil, nil, err
	}

	c.DeriveKeys(c.Metadata, tag3DH, c.NonceU, nonceS, ikm)

	var serverInfo []byte
	if len(ke2.Einfo) != 0 {
		pad := c.Hash.HKDFExpand(c.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	c.Transcript2 = utils.Concatenate(0, c.Metadata.CredReq, c.NonceU, internal.EncodeVector(c.Metadata.ClientInfo), c.Epk.Bytes(), c.Metadata.CredResp, nonceS, ke2.EpkS, internal.EncodeVector(ke2.Einfo))

	if !checkHmac(c.Hash, c.Transcript2, c.ServerMac, ke2.Mac) {
		return nil, nil, internal.ErrAkeInvalidServerMac
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	return Ke3{Mac: c.Hmac(c.Transcript3, c.ClientMac)}.Serialize(), serverInfo, nil
}

func (c *Client) KeyGen() (sk, pk []byte) {
	switch c.Identifier() {
	case SigmaI:
		return sigmai.KeyGen()
	case TripleDH:
		return KeyGen(c.Group)
	default:
		panic("invalid")
	}
}

func (c *Client) PublicKey(sku []byte) []byte {
	if c.Identifier() == SigmaI {
		sig := signature.Ed25519.New()
		sig.SetPrivateKey(sku)

		return sig.GetPublicKey()
	} else {
		sk, err := c.Ake.Group.NewScalar().Decode(sku)
		if err != nil {
			panic(err)
		}

		return c.Ake.Group.Base().Mult(sk).Bytes()
	}
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
