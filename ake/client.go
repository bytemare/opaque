package ake

import (
	"crypto/hmac"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	*Ake
	NonceU []byte // todo: only useful in testing, to force value
}

func NewClient(id ciphersuite.Identifier, kdf *internal.KDF, mac *internal.Mac, h *internal.Hash) *Client {
	return &Client{
		Ake: &Ake{
			Identifier: id,
			Group:      id.Get(nil),
			KDF:        kdf,
			Mac:        mac,
			Hash:       h,
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
	c.Initialize(nil, nil, 32)

	return &message.KE1{
		NonceU:     c.NonceU,
		ClientInfo: clientInfo,
		EpkU:       internal.SerializePoint(c.Epk, c.Identifier),
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

	transcriptHasher := c.Hash.H
	newInfo(transcriptHasher, ke1, idu, ids, ke2.CredentialResponse.Serialize(), ke2.NonceS, ke2.EpkS)
	keys := deriveKeys(c.KDF, ikm, transcriptHasher.Sum(nil))
	var serverInfo []byte

	if len(ke2.Einfo) != 0 {
		pad := c.Expand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	_, _ = transcriptHasher.Write(internal.EncodeVector(ke2.Einfo))
	transcript2 := transcriptHasher.Sum(nil)

	expected := c.MAC(keys.ServerMacKey, transcript2)
	if !hmac.Equal(expected, ke2.Mac) {
		return nil, nil, ErrAkeInvalidServerMac
	}

	_, _ = transcriptHasher.Write(ke2.Mac)
	transcript3 := transcriptHasher.Sum(nil)
	c.Keys = keys
	c.SessionSecret = keys.SessionSecret

	return &message.KE3{Mac: c.MAC(keys.ClientMacKey, transcript3)}, serverInfo, nil
}

func (c *Client) SessionKey() []byte {
	return c.SessionSecret
}
