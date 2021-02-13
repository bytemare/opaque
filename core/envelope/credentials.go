package envelope

import (
	"errors"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

var ErrCredsInvalidMode = errors.New("credentials - invalid ClearTextCredentials mode")

type SecretCredentials struct {
	Sku []byte
}

func (s *SecretCredentials) Serialize() []byte {
	return internal.EncodeVector(s.Sku)
}

func DeserializeSecretCredentials(in []byte) (sk *SecretCredentials, err error) {
	skU, _, err := internal.DecodeVector(in)
	if err != nil {
		return nil, err
	}

	return &SecretCredentials{skU}, nil
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
	return internal.EncodeVector(b.Pks)
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
	return utils.Concatenate(0, internal.EncodeVector(c.Pks), internal.EncodeVector(c.Idu), internal.EncodeVector(c.Ids))
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
