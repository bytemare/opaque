package envelope

import (
	"errors"

	"github.com/bytemare/cryptotools/encoding"
)

var errEnvelopeDecode = errors.New("could not decode envelope")

type Mode byte

const (
	Base Mode = iota + 1
	CustomIdentifier

	sBase             = "Base"
	sCustomIdentifier = "CustomIdentifier"
)

func (e Mode) String() string {
	switch e {
	case Base:
		return sBase
	case CustomIdentifier:
		return sCustomIdentifier
	default:
		return ""
	}
}

type Envelope struct {
	Contents InnerEnvelope `json:"e"`
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
		return nil, errEnvelopeDecode
	}

	return env, nil
}

type InnerEnvelope struct {
	Mode           Mode   `json:"m"`
	Nonce          []byte `json:"n"`
	EncryptedCreds []byte `json:"c"`
}
