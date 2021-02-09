package tripledh

import (
	"fmt"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/engine"
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

func Response(c *engine.Ake, m *engine.Metadata, sk, pku, req, serverInfo []byte) ([]byte, error) {
	ke1, err := engine.DeserializeKe1(req, c.NonceLen, c.Group.ElementLength())
	if err != nil {
		return nil, err
	}

	m.ClientInfo = ke1.ClientInfo

	ikm, err := serverK3dh(c, sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	c.DeriveKeys(m, tag3DH, ke1.NonceU, c.NonceS, ikm)

	var einfo []byte
	if len(serverInfo) != 0 {
		pad := c.Hash.HKDFExpand(c.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, ke1.NonceU, internal.EncodeVector(m.ClientInfo), ke1.EpkU, m.CredResp, c.NonceS, c.Epk.Bytes(), internal.EncodeVector(einfo))

	return Ke2{
		NonceS: c.NonceS,
		EpkS:   c.Epk.Bytes(),
		Einfo:  einfo,
		Mac:    c.Hmac(c.Transcript2, c.ServerMac),
	}.Serialize(), nil
}

func ServerFinalize(core *engine.Ake, req []byte) error {
	ke3, err := DeserializeKe3(req, core.Hash.OutputSize())
	if err != nil {
		return err
	}

	core.Transcript3 = utils.Concatenate(0, core.Transcript2)

	if !checkHmac(core.Hash, core.Transcript3, core.ClientMac, ke3.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}
