package sigmai

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

func Finalize(core *internal.Core, m *internal.Metadata, sku, pks, message, einfo2 []byte, enc encoding.Encoding) ([]byte, error) {
	ke2, err := decodeke2(message, enc)
	if err != nil {
		return nil, err
	}

	ikm, err := kSigma(core.Group, core.Esk, ke2.EpkS)
	if err != nil {
		return nil, err
	}

	core.DeriveKeys(m, tagSigmaI, core.NonceU, ke2.NonceS, ikm)

	var info2 []byte
	if einfo2 != nil {
		info2, err = internal.AesGcmDecrypt(core.Ke2, einfo2)
		if err != nil {
			return nil, err
		}
	}

	core.Transcript2 = utils.Concatenate(0, m.CredReq, core.NonceU, m.Info1, core.Epk.Bytes(), m.CredResp, ke2.NonceS, info2, ke2.EpkS, einfo2)

	if !signature.Ed25519.Verify(pks, core.Transcript2, ke2.Signature) {
		return nil, ErrSigmaInvServerSig
	}

	if !checkHmac(core.Hash, m.IDs, core.Km2, ke2.Mac) {
		return nil, internal.ErrAkeInvalidServerMac
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2)

	return ke3{
		Signature: signature.Ed25519.Sign(sku, core.Transcript3),
		Mac:       core.Hmac(m.IDu, core.Km3),
	}.Encode(enc), nil
}
