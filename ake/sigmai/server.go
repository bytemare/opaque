package sigmai

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/internal"
)

func Response(c *engine.Ake, m *engine.Metadata, sk, pku, req, info2 []byte, enc encoding.Encoding) (encKe2, einfo2 []byte, err error) {
	ke1, err := engine.DecodeKe1(req, enc)
	if err != nil {
		return nil, nil, err
	}

	c.Idu = m.IDu
	c.Pku = pku

	c.Esk = c.NewScalar().Random()
	c.Epk = c.Base().Mult(c.Esk)
	c.NonceS = utils.RandomBytes(c.NonceLen)

	ikm, err := kSigma(c.Group, c.Esk, ke1.EpkU)
	if err != nil {
		return nil, nil, err
	}

	c.DeriveKeys(m, tagSigmaI, ke1.NonceU, c.NonceS, ikm)

	if info2 != nil {
		einfo2 = engine.AesGcmEncrypt(c.Ke2, info2)
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, ke1.NonceU, m.Info1, ke1.EpkU, m.CredResp, c.NonceS, info2, c.Epk.Bytes(), einfo2)

	sig := sig.Sign(sk, c.Transcript2)

	k := Ke2{
		NonceS:    c.NonceS,
		EpkS:      c.Epk.Bytes(),
		Signature: sig,
		Mac:       c.Hmac(m.IDs, c.Km2),
	}

	return k.Encode(enc), einfo2, nil
}

func ServerFinalize(c *engine.Ake, req []byte, enc encoding.Encoding) error {
	ke3, err := DecodeKe3(req, enc)
	if err != nil {
		return err
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	if !sig.Verify(c.Pku, c.Transcript3, ke3.Signature) {
		return ErrSigmaInvClientSig
	}

	if !checkHmac(c.Hash, c.Idu, c.Km3, ke3.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}
