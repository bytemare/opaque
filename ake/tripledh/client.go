package tripledh

import (
	"github.com/bytemare/cryptotools/encoding"
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

func Finalize(c *engine.Ake, m *engine.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error) {
	ke2, err := Decodeke2(message, enc)
	if err != nil {
		return nil, err
	}

	nonceS := ke2.NonceS

	ikm, err := clientK3dh(c.Group, c.Esk, sku, ke2.EpkS, pks)
	if err != nil {
		return nil, err
	}

	c.DeriveKeys(m, tag3DH, c.NonceU, nonceS, ikm)

	var info2 []byte
	if einfo2 != nil {
		info2, err = engine.AesGcmDecrypt(c.Ke2, einfo2)
		if err != nil {
			return nil, err
		}
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, c.NonceU, m.Info1, c.Epk.Bytes(), m.CredResp, nonceS, info2, ke2.EpkS, einfo2)

	if !checkHmac(c.Hash, c.Transcript2, c.Km2, ke2.Mac) {
		return nil, internal.ErrAkeInvalidServerMac
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	return Ke3{Mac: c.Hmac(c.Transcript3, c.Km3)}.Encode(enc), nil
}
