package message

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/envelope"
)

type Credentials interface {
	EnvelopeMode() envelope.Mode
	ServerPublicKey() []byte
	UserID() []byte
	ServerID() []byte
}

type BaseCleartextCredentials struct {
	envelope.Mode
	Pks []byte
}

type CustomCleartextCredentials struct {
	envelope.Mode
	Pks []byte
	Idu []byte
	Ids []byte
}

// NewClearTextCredentials returns either a base or custom Credentials struct.
// The arguments MUST be provided in the following order: (mode, ServerPublicKey, UserID, ServerID).
// Note that UserID and ServerID only have to be provided in CustomIdentifier mode.
func NewClearTextCredentials(mode envelope.Mode, args ...[]byte) Credentials {
	switch mode {
	case envelope.Base:
		return newBaseClearTextCredentials(args[0])
	case envelope.CustomIdentifier:
		return newCustomClearTextCredentials(args[0], args[1], args[2])
	default:
		panic(ErrCredsInvalidMode)
	}
}

func newBaseClearTextCredentials(pks []byte) *BaseCleartextCredentials {
	return &BaseCleartextCredentials{
		Mode: envelope.Base,
		Pks:  pks,
	}
}

func (b *BaseCleartextCredentials) EnvelopeMode() envelope.Mode {
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
		Mode: envelope.CustomIdentifier,
		Pks:  pks,
		Idu:  idu,
		Ids:  ids,
	}
}

func (c *CustomCleartextCredentials) EnvelopeMode() envelope.Mode {
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

func EncodeClearTextCredentials(mode envelope.Mode, creds Credentials, enc encoding.Encoding) (encClear []byte, err error) {
	if mode == envelope.CustomIdentifier {
		clear := NewClearTextCredentials(
			envelope.CustomIdentifier,
			creds.ServerPublicKey(),
			creds.UserID(),
			creds.ServerID())

		encClear, err = enc.Encode(clear)
		if err != nil {
			return nil, err
		}
	} else {
		clear := NewClearTextCredentials(envelope.Base, creds.ServerPublicKey())
		encClear, err = enc.Encode(clear)
		if err != nil {
			return nil, err
		}
	}

	return encClear, nil
}
