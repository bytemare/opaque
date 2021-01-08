package sigmai

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

func Response(core *internal.Core, m *internal.Metadata, nonceLen int, sk, pku, req, info2 []byte, enc encoding.Encoding) ([]byte, []byte, error) {
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

	var einfo2 []byte
	if info2 != nil {
		// Todo : encrypt info2 to einfo2 with ke2
	}

	core.Transcript2 = utils.Concatenate(0, m.CredReq, ke1.NonceU, m.Info1, ke1.EpkU, m.CredResp, core.NonceS, info2, core.Epk.Bytes(), einfo2)

	sig := core.Sign(sk, core.Transcript2)

	return ke2{
		NonceS:    core.NonceS,
		EpkS:      core.Epk.Bytes(),
		Signature: sig,
		Mac:       core.Hmac(m.IDs, core.Km2),
	}.Encode(enc), einfo2, nil
}

func ServerFinalize(core *internal.Core, info3, einfo3, req []byte, enc encoding.Encoding) error {
	if info3 != nil && einfo3 != nil {
		panic("")
	}

	ke3, err := decodeKe3(req, enc)
	if err != nil {
		return err
	}

	if einfo3 != nil {
		// todo decrypt einfo3 into info with ke3
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2, info3, einfo3)

	if !core.Verify(core.Pku, core.Transcript3, ke3.Signature) {
		return errors.New("invalid signature")
	}


	if !checkHmac(core.Hash, core.Idu, core.Km3, ke3.Mac) {
		return errors.New("invalid mac")
	}

	return nil
}