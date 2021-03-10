package envelope

import (
	"errors"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
)

type Mode byte

const (
	Base Mode = iota + 1
	CustomIdentifier
	Seed

	sBase             = "Base"
	sCustomIdentifier = "CustomIdentifier"
)

func (e Mode) Get() EnvMode {
	switch e {
	case Base:
		return &BaseMode{}
	case CustomIdentifier:
		return &CustomMode{}
	case Seed:
		return &SeedMode{}
	default:
		panic("invalid mode")
	}
}

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

type EnvMode interface {
	BuildInnerEnvelope(prk []byte, creds *Credentials, k *Keys) *InnerEnvelope
	ClearTextCredentials(idu, ids, pks []byte) CleartextCredentials
	Recover(prk []byte, k *Keys, inner *InnerEnvelope) *SecretCredentials
}

type Envelope struct {
	InnerEnv *InnerEnvelope `json:"e"`
	AuthTag  []byte         `json:"t"`
}

func (e *Envelope) Serialize() []byte {
	return append(e.InnerEnv.Serialize(), e.AuthTag...)
}

func DeserializeEnvelope(in []byte, Nh, skLength int) (envU *Envelope, offset int, err error) {
	contents, length, err := deserializeInnerEnvelope(in, skLength)
	if err != nil {
		return nil, 0, err
	}

	if len(in) < length+Nh {
		return nil, 0, errors.New("decode envelope: insufficient bytes")
	}

	authTag := in[length : length+Nh]

	return &Envelope{contents, authTag}, length + Nh, nil
}

type InnerEnvelope struct {
	Mode           Mode   `json:"m"`
	Nonce          []byte `json:"n,omitempty"`
	EncryptedCreds []byte `json:"c,omitempty"`
}

func (i *InnerEnvelope) Serialize() []byte {
	return utils.Concatenate(0, encoding.I2OSP(int(i.Mode), 1), i.Nonce, i.EncryptedCreds)
}

func deserializeInnerEnvelope(in []byte, skLength int) (*InnerEnvelope, int, error) {
	header := 1 + nonceLen
	if len(in) < header+skLength {
		return nil, 0, errors.New("insufficient length of inner envelope")
	}

	mode := encoding.OS2IP(in[0:1])
	nonce := in[1:header]
	ct := in[header : header+skLength]

	return &InnerEnvelope{Mode(mode), nonce, ct}, header + len(ct), nil
}
