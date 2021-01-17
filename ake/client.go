package ake

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/ake/sigmai"
	"github.com/bytemare/opaque/ake/tripledh"
)

type clientFinalize func(core *engine.Ake, m *engine.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error)

type Client struct {
	id Identifier
	*engine.Ake
	*engine.Metadata
	clientFinalize
}

func (c *Client) Identifier() Identifier {
	return c.id
}

func (c *Client) Start() *engine.Ke1 {
	c.Esk = c.NewScalar().Random()
	c.Epk = c.Base().Mult(c.Esk)
	c.NonceU = utils.RandomBytes(c.NonceLen)

	return &engine.Ke1{
		NonceU: c.NonceU,
		EpkU:   c.Epk.Bytes(),
	}
}

func (c *Client) Finalize(sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error) {
	return c.clientFinalize(c.Ake, c.Metadata, sku, pks, message, einfo2, enc)
}

func (c *Client) KeyGen() (sk, pk []byte) {
	switch c.Identifier() {
	case SigmaI:
		return sigmai.KeyGen()
	case TripleDH:
		return tripledh.KeyGen(c.Group)
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
