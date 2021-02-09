package sigmai

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
)

func Finalize(c *ake.Ake, m *ake.Metadata, sku, pks, message []byte) ([]byte, []byte, error) {
	ke2, err := DeserializeKe2(message, c.NonceLen, c.Group.ElementLength(), int(sig.SignatureLength()), c.Hash.OutputSize())
	if err != nil {
		return nil, nil, err
	}

	ikm, err := kSigma(c.Group, c.Esk, ke2.EpkS)
	if err != nil {
		return nil, nil, err
	}

	c.DeriveKeys(m, tagSigmaI, c.NonceU, ke2.NonceS, ikm)

	var serverInfo []byte
	if len(ke2.EInfo) != 0 {
		pad := c.Hash.HKDFExpand(c.HandshakeEncryptKey, []byte(encryptionTag), len(ke2.EInfo))
		serverInfo = internal.Xor(pad, ke2.EInfo)
	}

	c.Transcript2 = utils.Concatenate(0, m.CredReq, c.NonceU, m.ClientInfo, c.Epk.Bytes(), m.CredResp, ke2.NonceS, serverInfo, ke2.EpkS, ke2.EInfo)

	if !sig.Verify(pks, c.Transcript2, ke2.Signature) {
		return nil, nil, ErrSigmaInvServerSig
	}

	if !checkHmac(c.Hash, m.IDs, c.ServerMac, ke2.Mac) {
		return nil, nil, internal.ErrAkeInvalidServerMac
	}

	c.Transcript3 = utils.Concatenate(0, c.Transcript2)

	return Ke3{
		Signature: sig.Sign(sku, c.Transcript3),
		Mac:       c.Hmac(m.IDu, c.ClientMac),
	}.Serialize(), serverInfo, nil
}
