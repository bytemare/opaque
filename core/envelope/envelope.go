package envelope

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
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

func (e *Envelope) Serialize() []byte {
	return append(e.Contents.Serialize(), e.AuthTag...)
}

func DeserializeEnvelope(in []byte, Nh int) (*Envelope, int, error) {
	contents, offset := DeserializeInnerEnvelope(in)
	if len(in) < offset+Nh {
		return nil, 0, errors.New("decode envelope: Insufficient bytes")
	}
	authTag := in[offset : offset+Nh]
	return &Envelope{*contents, authTag}, offset + Nh, nil
}

type InnerEnvelope struct {
	Mode           Mode   `json:"m"`
	Nonce          []byte `json:"n"`
	EncryptedCreds []byte `json:"c"`
}

func (i *InnerEnvelope) Serialize() []byte {
	return utils.Concatenate(0, encoding.I2OSP(int(i.Mode), 1), i.Nonce, internal.EncodeVector(i.EncryptedCreds))
}

func DeserializeInnerEnvelope(in []byte) (*InnerEnvelope, int) {
	if len(in) < nonceLen+2 {
		panic("Insufficient bytes")
	}
	mode := encoding.OS2IP(in[0:1])
	nonce := in[1 : nonceLen+1]
	ct, ctOffset := internal.DecodeVector(in[nonceLen+1:])
	return &InnerEnvelope{Mode(mode), nonce, ct}, nonceLen + 1 + ctOffset
}
