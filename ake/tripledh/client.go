package tripledh

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/internal"
)

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

func Finalize(c *engine.Ake, m *engine.Metadata, sku, pks, message []byte) ([]byte, []byte, error) {
	ke2, err := DeserializeKe2(message, c.NonceLen, c.Group.ElementLength(), c.Hash.OutputSize())
	if err != nil {
		return nil, nil, err
	}

	nonceS := ke2.NonceS

	ikm, err := clientK3dh(c.Group, c.Esk, sku, ke2.EpkS, pks)
	if err != nil {
		return nil, nil, err
	}

	c.DeriveKeys(m, tag3DH, c.NonceU, nonceS, ikm)

	var serverInfo []byte
	if len(ke2.Einfo) != 0 {
		pad := c.Hash.HKDFExpand(c.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.Einfo))
		serverInfo = internal.Xor(pad, ke2.Einfo)
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, c.NonceU, internal.EncodeVector(m.ClientInfo), c.Epk.Bytes(), m.CredResp, nonceS, ke2.EpkS, internal.EncodeVector(ke2.Einfo))

	if !checkHmac(c.Hash, c.Transcript2, c.ServerMac, ke2.Mac) {
		return nil, nil, internal.ErrAkeInvalidServerMac
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	return Ke3{Mac: c.Hmac(c.Transcript3, c.ClientMac)}.Serialize(), serverInfo, nil
}
