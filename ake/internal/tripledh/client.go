package tripledh

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
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

func Finalize(core *internal.Core, m *internal.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error) {
	ke2, err := decodeke2(message, enc)
	if err != nil {
		return nil, err
	}

	nonceS := ke2.NonceS

	ikm, err := clientK3dh(core.Group, core.Esk, sku, ke2.EpkS, pks)
	if err != nil {
		return nil, err
	}

	core.DeriveKeys(m, tag3DH, core.NonceU, nonceS, ikm)

	var info2 []byte
	if einfo2 != nil {
		info2, err = internal.AesGcmDecrypt(core.Ke2, einfo2)
		if err != nil {
			return nil, err
		}
	}

	core.Transcript2 = utils.Concatenate(0, m.CredReq, core.NonceU, m.Info1, core.Epk.Bytes(), m.CredResp, nonceS, info2, ke2.EpkS, einfo2)

	if !checkHmac(core.Hash, core.Transcript2, core.Km2, ke2.Mac) {
		return nil, internal.ErrAkeInvalidServerMac
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2)

	return ke3{Mac: core.Hmac(core.Transcript3, core.Km3)}.Encode(enc), nil
}
