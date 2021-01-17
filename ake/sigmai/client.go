package sigmai

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/internal"
)

func Finalize(c *engine.Ake, m *engine.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error) {
	ke2, err := Decodeke2(message, enc)
	if err != nil {
		return nil, err
	}

	ikm, err := kSigma(c.Group, c.Esk, ke2.EpkS)
	if err != nil {
		return nil, err
	}

	c.DeriveKeys(m, tagSigmaI, c.NonceU, ke2.NonceS, ikm)

	var info2 []byte
	if einfo2 != nil {
		info2, err = engine.AesGcmDecrypt(c.Ke2, einfo2)
		if err != nil {
			return nil, err
		}
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, c.NonceU, m.Info1, c.Epk.Bytes(), m.CredResp, ke2.NonceS, info2, ke2.EpkS, einfo2)

	if !sig.Verify(pks, c.Transcript2, ke2.Signature) {
		return nil, ErrSigmaInvServerSig
	}

	if !checkHmac(c.Hash, m.IDs, c.Km2, ke2.Mac) {
		return nil, internal.ErrAkeInvalidServerMac
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	return Ke3{
		Signature: signature.Ed25519.Sign(sku, c.Transcript3),
		Mac:       c.Hmac(m.IDu, c.Km3),
	}.Encode(enc), nil
}
