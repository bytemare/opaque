package envelope

import (
	"github.com/bytemare/cryptotools/encoding"
)

type Credentials struct {
	Sk, Pk, Idu, Ids []byte
}

type CleartextCredentials interface {
	EnvelopeMode() Mode
	ServerPublicKey() []byte
	UserID() []byte
	ServerID() []byte
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

func EncodeClearTextCredentials(idu, ids, pks []byte, mode Mode, enc encoding.Encoding) (encClear []byte, err error) {
	var clear CleartextCredentials
	if mode == CustomIdentifier {
		clear = newCustomClearTextCredentials(pks, idu, ids)
	} else {
		clear = NewClearTextCredentials(Base, pks)
	}

	encClear, err = enc.Encode(clear)
	if err != nil {
		return nil, err
	}

	return encClear, nil
}
