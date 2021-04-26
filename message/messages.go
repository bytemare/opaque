package message

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal/encode"
)

// Protocol Messages

type KE1 struct {
	*CredentialRequest
	NonceU     []byte `json:"n"`
	ClientInfo []byte `json:"i"`
	EpkU       []byte `json:"e"`
}

func (m *KE1) Serialize() []byte {
	return utils.Concatenate(0, m.CredentialRequest.Serialize(), m.NonceU, encode.EncodeVector(m.ClientInfo), m.EpkU)
}

type KE2 struct {
	*CredentialResponse
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Einfo  []byte `json:"i"`
	Mac    []byte `json:"m"`
}

func (m *KE2) Serialize() []byte {
	return utils.Concatenate(0, m.CredentialResponse.Serialize(), m.NonceS, m.EpkS, encode.EncodeVector(m.Einfo), m.Mac)
}

type KE3 struct {
	Mac []byte `json:"m"`
}

func (k KE3) Serialize() []byte {
	return k.Mac
}

type Message interface {
	Serialize() []byte
}
