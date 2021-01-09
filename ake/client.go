package ake

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type clientFinalize func(core *internal.Core, m *internal.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error)

type Client struct {
	id Identifier
	*internal.Core
	clientFinalize
}

func (c *Client) Identifier() Identifier {
	return c.id
}

func (c *Client) Start(nonceLen int, enc encoding.Encoding) []byte {
	c.Esk = c.NewScalar().Random()
	c.Epk = c.Base().Mult(c.Esk)
	c.NonceU = utils.RandomBytes(nonceLen)

	return internal.Ke1{
		NonceU: c.NonceU,
		EpkU:   c.Epk.Bytes(),
	}.Encode(enc)
}

func (c *Client) Finalize(m *internal.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error) {
	return c.clientFinalize(c.Core, m, sku, pks, message, einfo2, enc)
}

func (c *Client) SessionKey() []byte {
	return c.SessionSecret
}