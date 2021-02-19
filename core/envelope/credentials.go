package envelope

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type SecretCredentials struct {
	Sku []byte
}

func (s *SecretCredentials) Serialize() []byte {
	return s.Sku
}

func DeserializeSecretCredentials(input []byte) *SecretCredentials {
return &SecretCredentials{input}
}

type cleartextCredentials interface {
	Serialize() []byte
}

type baseCleartextCredentials struct {
	Mode
	Pks []byte
}

type customCleartextCredentials struct {
	Mode
	Pks []byte
	Idu []byte
	Ids []byte
}

func newBaseClearTextCredentials(pks []byte) *baseCleartextCredentials {
	return &baseCleartextCredentials{
		Mode: Base,
		Pks:  pks,
	}
}

func (b *baseCleartextCredentials) Serialize() []byte {
	return b.Pks
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
	return utils.Concatenate(0, c.Pks, internal.EncodeVector(c.Idu), internal.EncodeVector(c.Ids))
}

func encodeClearTextCredentials(idu, ids, pks []byte, mode Mode) []byte {
	switch mode {
	case Base:
		return newBaseClearTextCredentials(pks).Serialize()
	case CustomIdentifier:
		return newCustomClearTextCredentials(pks, idu, ids).Serialize()
	default:
		panic("invalid mode")
	}
}

type Credentials struct {
	Sk, Pk, Idu, Ids, Nonce []byte
}
