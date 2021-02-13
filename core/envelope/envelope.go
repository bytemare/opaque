package envelope

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

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

func DeserializeEnvelope(in []byte, Nh int) (envU *Envelope, offset int, err error) {
	contents, length, err := deserializeInnerEnvelope(in)
	if err != nil {
		return nil, 0, err
	}

	if len(in) < length+Nh {
		return nil, 0, errors.New("decode envelope: insufficient bytes")
	}
	authTag := in[length : length+Nh]
	return &Envelope{*contents, authTag}, length + Nh, nil
}

type InnerEnvelope struct {
	Mode           Mode   `json:"m"`
	Nonce          []byte `json:"n"`
	EncryptedCreds []byte `json:"c"`
}

func (i *InnerEnvelope) Serialize() []byte {
	return utils.Concatenate(0, encoding.I2OSP(int(i.Mode), 1), i.Nonce, internal.EncodeVector(i.EncryptedCreds))
}

func deserializeInnerEnvelope(in []byte) (*InnerEnvelope, int, error) {
	if len(in) < nonceLen+2 {
		return nil, 0, errors.New("insufficient length of inner envelope")
	}

	mode := encoding.OS2IP(in[0:1])
	nonce := in[1 : nonceLen+1]

	ct, ctOffset, err := internal.DecodeVector(in[nonceLen+1:])
	if err != nil {
		return nil, 0, err
	}

	return &InnerEnvelope{Mode(mode), nonce, ct}, nonceLen + 1 + ctOffset, nil
}
