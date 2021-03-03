package ake

import (
	"crypto/hmac"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	*Ake
	NonceU []byte // todo: only useful in testing, to force value
}

func NewClient(g ciphersuite.Identifier, h hash.Hashing) *Client {
	return &Client{
		Ake: &Ake{
			Group:   g.Get(nil),
			Hashing: h,
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
	c.Ake.Initialize(nil, nil, 32)

	return &message.KE1{
		NonceU:     c.NonceU,
		ClientInfo: clientInfo,
		EpkU:       c.Epk.Bytes(),
	}
}

func (c *Client) ikm(skc, epks, pks []byte) ([]byte, error) {
	sk, epk, gpk, err := decodeKeys(c.Group, skc, epks, pks)
	if err != nil {
		return nil, err
	}

	return k3dh(epk, c.Esk, gpk, c.Esk, epk, sk), nil
}

func (c *Client) Finalize(idu, skc, ids, pks []byte, ke1 *message.KE1, ke2 *message.KE2) (*message.KE3, []byte, error) {
	ikm, err := c.ikm(skc, ke2.EpkS, pks)
	if err != nil {
		return nil, nil, err
	}

	h := c.Hashing.Get()
	transcriptHasher := c.Hashing.Get()
	newInfo(transcriptHasher, ke1, idu, ids, ke2.CredentialResponse.Serialize(), ke2.NonceS, ke2.EpkS)

	keys := deriveKeys(h, ikm, transcriptHasher.Sum(nil))

	var serverInfo []byte

	if len(ke2.Einfo) != 0 {
		pad := h.HKDFExpand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	_, _ = transcriptHasher.Write(internal.EncodeVector(ke2.Einfo))
	transcript2 := transcriptHasher.Sum(nil)

	expected := h.Hmac(transcript2, keys.ServerMacKey)
	if !hmac.Equal(expected, ke2.Mac) {
		return nil, nil, ErrAkeInvalidServerMac
	}

	_, _ = transcriptHasher.Write(ke2.Mac)
	transcript3 := transcriptHasher.Sum(nil)
	c.Keys = keys
	c.SessionSecret = keys.SessionSecret

	return &message.KE3{Mac: h.Hmac(transcript3, keys.ClientMacKey)}, serverInfo, nil
}

func (c *Client) SessionKey() []byte {
	return c.SessionSecret
}
