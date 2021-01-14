package sigmai

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

func Response(core *internal.Core, m *internal.Metadata, nonceLen int, sk, pku, req, info2 []byte, enc encoding.Encoding) (encKe2, einfo2 []byte, err error) {
	ke1, err := internal.DecodeKe1(req, enc)
	if err != nil {
		return nil, nil, err
	}

	core.Idu = m.IDu
	core.Pku = pku

	core.Esk = core.NewScalar().Random()
	core.Epk = core.Base().Mult(core.Esk)
	core.NonceS = utils.RandomBytes(nonceLen)

	ikm, err := kSigma(core.Group, core.Esk, ke1.EpkU)
	if err != nil {
		return nil, nil, err
	}

	core.DeriveKeys(m, tagSigmaI, ke1.NonceU, core.NonceS, ikm)

	if info2 != nil {
		einfo2, err = internal.AesGcmDecrypt(core.Ke2, info2)
		if err != nil {
			return nil, nil, err
		}
	}

	core.Transcript2 = utils.Concatenate(0, m.CredReq, ke1.NonceU, m.Info1, ke1.EpkU, m.CredResp, core.NonceS, info2, core.Epk.Bytes(), einfo2)

	sig := core.Sign(sk, core.Transcript2)

	k := ke2{
		NonceS:    core.NonceS,
		EpkS:      core.Epk.Bytes(),
		Signature: sig,
		Mac:       core.Hmac(m.IDs, core.Km2),
	}

	return k.Encode(enc), einfo2, nil
}

func ServerFinalize(core *internal.Core, req []byte, enc encoding.Encoding) error {
	ke3, err := decodeKe3(req, enc)
	if err != nil {
		return err
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2)

	if !core.Verify(core.Pku, core.Transcript3, ke3.Signature) {
		return ErrSigmaInvClientSig
	}

	if !checkHmac(core.Hash, core.Idu, core.Km3, ke3.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}
