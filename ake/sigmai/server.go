package sigmai

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/internal"
)

func Response(c *engine.Ake, m *engine.Metadata, sk, pku, req, serverInfo []byte) (encKe2 []byte, err error) {
	ke1, err := engine.DeserializeKe1(req, c.NonceLen, c.Group.ElementLength())
	if err != nil {
		return nil, err
	}

	m.ClientInfo = ke1.ClientInfo
	c.Idu = m.IDu
	c.Pku = pku

	ikm, err := kSigma(c.Group, c.Esk, ke1.EpkU)
	if err != nil {
		return nil, err
	}

	c.DeriveKeys(m, tagSigmaI, ke1.NonceU, c.NonceS, ikm)

	var einfo []byte
	if len(serverInfo) != 0 {
		pad := c.Hash.HKDFExpand(c.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, ke1.NonceU, m.ClientInfo, ke1.EpkU, m.CredResp, c.NonceS, serverInfo, c.Epk.Bytes(), einfo)

	sig := sig.Sign(sk, c.Transcript2)

	k := Ke2{
		NonceS:    c.NonceS,
		EpkS:      c.Epk.Bytes(),
		EInfo:     einfo,
		Signature: sig,
		Mac:       c.Hmac(m.IDs, c.ServerMac),
	}

	return k.Serialize(), nil
}

func ServerFinalize(c *engine.Ake, req []byte) error {
	ke3, err := DeserializeKe3(req, int(sig.SignatureLength()), c.Hash.OutputSize())
	if err != nil {
		return err
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	if !sig.Verify(c.Pku, c.Transcript3, ke3.Signature) {
		return ErrSigmaInvClientSig
	}

	if !checkHmac(c.Hash, c.Idu, c.ClientMac, ke3.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}
