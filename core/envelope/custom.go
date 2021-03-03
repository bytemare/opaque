package envelope

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type customCleartextCredentials struct {
	Mode
	Pks []byte
	Idu []byte
	Ids []byte
}

func newCustomClearTextCredentials(pks, idu, ids []byte) *customCleartextCredentials {
	return &customCleartextCredentials{
		Mode: CustomIdentifier,
		Pks:  pks,
		Idu:  idu,
		Ids:  ids,
	}
}

func (c *customCleartextCredentials) Serialize() []byte {
	var u, s []byte
	if c.Idu != nil {
		u = internal.EncodeVector(c.Idu)
	}

	if c.Ids != nil {
		s = internal.EncodeVector(c.Ids)
	}

	return utils.Concatenate(0, c.Pks, u, s)
}

type ClearTextCredentials struct {
	Mode
	Pks []byte
	Idu []byte
	Ids []byte
}

func (c *ClearTextCredentials) Serialize() []byte {
	var u, s []byte
	if c.Idu != nil {
		u = internal.EncodeVector(c.Idu)
	}
	if c.Ids != nil {
		s = internal.EncodeVector(c.Ids)
	}

	return utils.Concatenate(0, c.Pks, u, s)
}

type CustomMode struct{}

func (c CustomMode) BuildInnerEnvelope(prk []byte, creds *Credentials, k *Keys) *InnerEnvelope {
	sec := SecretCredentials{Sku: creds.Sk}
	pt := sec.Serialize()
	k.padKey(prk, len(pt))

	encryptedCreds := internal.Xor(pt, k.Pad)

	return &InnerEnvelope{
		Mode:           CustomIdentifier,
		Nonce:          creds.Nonce,
		EncryptedCreds: encryptedCreds,
	}
}

func (c CustomMode) ClearTextCredentials(idu, ids, pks []byte) CleartextCredentials {
	return newCustomClearTextCredentials(pks, idu, ids)
}

func (c CustomMode) Recover(prk []byte, k *Keys, inner *InnerEnvelope) *SecretCredentials {
	return BaseMode{}.Recover(prk, k, inner)
}
