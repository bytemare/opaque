package tripledh

import (
	"fmt"

	"github.com/bytemare/opaque/ake/engine"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

func serverK3dh(c *engine.Ake, sk, epku, pku []byte) ([]byte, error) {
	sks, err := c.NewScalar().Decode(sk)
	if err != nil {
		return nil, fmt.Errorf("sk : %w", err)
	}

	epk, err := c.NewElement().Decode(epku)
	if err != nil {
		return nil, fmt.Errorf("epku : %w", err)
	}

	gpk, err := c.NewElement().Decode(pku)
	if err != nil {
		return nil, fmt.Errorf("pku : %w", err)
	}

	e1 := epk.Mult(c.Esk)
	e2 := epk.Mult(sks)
	e3 := gpk.Mult(c.Esk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes()), nil
}

func Response(c *engine.Ake, m *engine.Metadata, sk, pku, req, info2 []byte, enc encoding.Encoding) (encKe2, einfo2 []byte, err error) {
	ke1, err := engine.DecodeKe1(req, enc)
	if err != nil {
		return nil, nil, err
	}

	c.Esk = c.NewScalar().Random()
	c.Epk = c.Base().Mult(c.Esk)
	c.NonceS = utils.RandomBytes(c.NonceLen)

	ikm, err := serverK3dh(c, sk, ke1.EpkU, pku)
	if err != nil {
		return nil, nil, err
	}

	c.DeriveKeys(m, tag3DH, ke1.NonceU, c.NonceS, ikm)

	if info2 != nil {
		einfo2, err = engine.AesGcmDecrypt(c.Ke2, info2)
		if err != nil {
			return nil, nil, err
		}
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, ke1.NonceU, m.Info1, ke1.EpkU, m.CredResp, c.NonceS, info2, c.Epk.Bytes(), einfo2)

	return Ke2{
		NonceS: c.NonceS,
		EpkS:   c.Epk.Bytes(),
		Mac:    c.Hmac(c.Transcript2, c.Km2),
	}.Encode(enc), einfo2, nil
}

func ServerFinalize(core *engine.Ake, req []byte, enc encoding.Encoding) error {
	ke3, err := DecodeKe3(req, enc)
	if err != nil {
		return err
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2)

	if !checkHmac(core.Hash, core.Transcript3, core.Km3, ke3.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}
