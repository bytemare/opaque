package sigmai

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

func Finalize(core *internal.Core, m *internal.Metadata, sku, pks, message, info2, einfo2, info3 []byte, enc encoding.Encoding) ([]byte, []byte, error) {
	ke2, err := decodeke2(message, enc)
	if err != nil {
		return nil, nil, err
	}

	ikm, err := kSigma(core.Group, core.Esk, ke2.EpkS)
	if err != nil {
		return nil, nil, err
	}

	core.DeriveKeys(m, tagSigmaI, core.NonceU, ke2.NonceS, ikm)

	if einfo2 != nil {
		// todo decrypt einfo2 into info2 with ke2
	}

	core.Transcript2 = utils.Concatenate(0, m.CredReq, core.NonceU, m.Info1, core.Epk.Bytes(), m.CredResp, ke2.NonceS, info2, ke2.EpkS, einfo2)

	if !signature.Ed25519.Verify(pks, core.Transcript2, ke2.Signature) {
		return nil, nil, errors.New("invalid signature")
	}

	if !checkHmac(core.Hash, m.IDs, core.Km2, ke2.Mac) {
		return nil, nil, errors.New("invalid mac")
	}

	var einfo3 []byte
	if info3 != nil {
		// todo encrypt info3 with ke3
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2, info3, einfo3)

	return ke3{
		Signature: signature.Ed25519.Sign(sku, core.Transcript3),
		Mac:       core.Hmac(m.IDu, core.Km3),
	}.Encode(enc), einfo3, nil
}