package ake

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type clientFinalize func(core *internal.Core, m *internal.Metadata, sku, pks, message, info2, einfo2, info3 []byte, enc encoding.Encoding) ([]byte, []byte, error)

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

func (c *Client) Finalize(m *internal.Metadata, sku, pks, message, info2, einfo2, info3 []byte, enc encoding.Encoding) ([]byte, []byte, error) {
	if einfo2 != nil && info2 != nil {
		// todo what happens here ?
		return nil, nil, errors.New("info2 and einfo2 are both non-nil")
	}

	return c.clientFinalize(c.Core, m, sku, pks, message, info2, einfo2, info3, enc)
}

func (c *Client) SessionKey() []byte {
	return c.SessionSecret
}