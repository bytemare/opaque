package opaque

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
)

type EnvelopeMode bool

const (
	Base             EnvelopeMode = true
	CustomIdentifier EnvelopeMode = false
)

type Envelope struct {
	Contents innerEnvelope `json:"e"`
	AuthTag  []byte        `json:"t"`
}

func (e *Envelope) Encode(enc encoding.Encoding) ([]byte, error) {
	return enc.Encode(e)
}

func DecodeEnvelope(e []byte, enc encoding.Encoding) (*Envelope, error) {
	en, err := enc.Decode(e, &Envelope{})
	if err != nil {
		return nil, err
	}

	env, ok := en.(*Envelope)
	if !ok {
		return nil, errors.New("could not decode envelope")
	}

	return env, nil
}

type innerEnvelope struct {
	Mode           EnvelopeMode
	Nonce          []byte `json:"n"`
	EncryptedCreds []byte `json:"c"`
}

type secretCredentials struct {
	Sku []byte
}

type Credentials interface {
	Mode() EnvelopeMode
	ServerPublicKey() []byte
	UserID() []byte
	ServerID() []byte
}

type BaseCleartextCredentials struct {
	EnvelopeMode
	Pks []byte
}

type CustomCleartextCredentials struct {
	EnvelopeMode
	Pks []byte
	Idu []byte
	Ids []byte
}

// NewClearTextCredentials returns either a base or custom Credentials struct.
// The arguments MUST be provided in the following order: (mode, ServerPublicKey, UserID, ServerID).
// Note that UserID and ServerID only have to be provided in CustomIdentifier mode.
func NewClearTextCredentials(mode EnvelopeMode, args ...[]byte) Credentials {
	switch mode {
	case Base:
		return newBaseClearTextCredentials(args[0])
	case CustomIdentifier:
		return newCustomClearTextCredentials(args[0], args[1], args[2])
	default:
		panic(errors.New("invalid ClearTextCredentials mode"))
	}
}

func newBaseClearTextCredentials(pks []byte) *BaseCleartextCredentials {
	return &BaseCleartextCredentials{
		EnvelopeMode: Base,
		Pks:          pks,
	}
}

func (b *BaseCleartextCredentials) Mode() EnvelopeMode {
	return b.EnvelopeMode
}

func (b *BaseCleartextCredentials) ServerPublicKey() []byte {
	return b.Pks
}

func (b *BaseCleartextCredentials) UserID() []byte {
	panic(errors.New("no idu in Base mode"))
}

func (b *BaseCleartextCredentials) ServerID() []byte {
	panic(errors.New("no ids in Base mode"))
}

func newCustomClearTextCredentials(pks, idu, ids []byte) *CustomCleartextCredentials {
	return &CustomCleartextCredentials{
		EnvelopeMode: CustomIdentifier,
		Pks:          pks,
		Idu:          idu,
		Ids:          ids,
	}
}

func (c *CustomCleartextCredentials) Mode() EnvelopeMode {
	return c.EnvelopeMode
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

func encodeClearTextCredentials(mode EnvelopeMode, creds Credentials, enc encoding.Encoding) (encClear []byte, err error) {
	if mode == CustomIdentifier {
		clear := NewClearTextCredentials(
			CustomIdentifier,
			creds.ServerPublicKey(),
			creds.UserID(),
			creds.ServerID())
		encClear, err = enc.Encode(clear)
		if err != nil {
			return nil, err
		}
	} else {
		clear := NewClearTextCredentials(Base, creds.ServerPublicKey())
		encClear, err = enc.Encode(clear)
		if err != nil {
			return nil, err
		}
	}

	return encClear, nil
}