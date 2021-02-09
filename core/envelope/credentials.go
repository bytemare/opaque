package envelope

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

func DeserializeSecretCredentials(in []byte) (*SecretCredentials, int) {
	skU, offset := internal.DecodeVector(in)
	return &SecretCredentials{skU}, offset
}

type SecretCredentials struct {
	Sku []byte
}

func (s *SecretCredentials) Serialize() []byte {
	return internal.EncodeVector(s.Sku)
}

type Credentials struct {
	Sk, Pk, Idu, Ids, Nonce []byte
}

type CleartextCredentials interface {
	EnvelopeMode() Mode
	ServerPublicKey() []byte
	UserID() []byte
	ServerID() []byte
	Serialize() []byte
}

type BaseCleartextCredentials struct {
	Mode
	Pks []byte
}

type CustomCleartextCredentials struct {
	Mode
	Pks []byte
	Idu []byte
	Ids []byte
}

// NewClearTextCredentials returns either a base or custom CleartextCredentials struct.
// The arguments MUST be provided in the following order: (mode, ServerPublicKey, UserID, ServerID).
// Note that UserID and ServerID only have to be provided in CustomIdentifier mode.
func NewClearTextCredentials(mode Mode, args ...[]byte) CleartextCredentials {
	switch mode {
	case Base:
		return newBaseClearTextCredentials(args[0])
	case CustomIdentifier:
		return newCustomClearTextCredentials(args[0], args[1], args[2])
	default:
		panic(ErrCredsInvalidMode)
	}
}

func newBaseClearTextCredentials(pks []byte) *BaseCleartextCredentials {
	return &BaseCleartextCredentials{
		Mode: Base,
		Pks:  pks,
	}
}

func (b *BaseCleartextCredentials) EnvelopeMode() Mode {
	return b.Mode
}

func (b *BaseCleartextCredentials) ServerPublicKey() []byte {
	return b.Pks
}

func (b *BaseCleartextCredentials) UserID() []byte {
	panic(ErrCredsBaseNoIDu)
}

func (b *BaseCleartextCredentials) ServerID() []byte {
	panic(ErrCredsBaseNiIDs)
}

func (b *BaseCleartextCredentials) Serialize() []byte {
	return internal.EncodeVector(b.Pks)
}

func newCustomClearTextCredentials(pks, idu, ids []byte) *CustomCleartextCredentials {
	return &CustomCleartextCredentials{
		Mode: CustomIdentifier,
		Pks:  pks,
		Idu:  idu,
		Ids:  ids,
	}
}

func (c *CustomCleartextCredentials) EnvelopeMode() Mode {
	return c.Mode
}

func (c *CustomCleartextCredentials) ServerPublicKey() []byte {
	return c.Pks
}

func (c *CustomCleartextCredentials) UserID() []byte {
	return c.Idu
}

func (c *CustomCleartextCredentials) ServerID() []byte {
	return c.Ids
}

func (c *CustomCleartextCredentials) Serialize() []byte {
	return utils.Concatenate(0, internal.EncodeVector(c.Pks), internal.EncodeVector(c.Idu), internal.EncodeVector(c.Ids))
}

func EncodeClearTextCredentials(idu, ids, pks []byte, mode Mode) []byte {
	switch mode {
	case Base:
		return newBaseClearTextCredentials(pks).Serialize()
	case CustomIdentifier:
		return newCustomClearTextCredentials(pks, idu, ids).Serialize()
	default:
		panic("invalid mode")
	}
}
