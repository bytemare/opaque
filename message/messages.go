package message

import (
	"errors"
	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type Message interface {
	Serialize() []byte
}

// Protocol Messages

type KE1 struct {
	*CredentialRequest
	NonceU     []byte `json:"n"`
	ClientInfo []byte `json:"i"`
	EpkU       []byte `json:"e"`
}

func (m *KE1) Serialize() []byte {
	return utils.Concatenate(0, m.CredentialRequest.Serialize(), m.NonceU, internal.EncodeVector(m.ClientInfo), m.EpkU)
}

func (m *KE1) Verify(_ group.Group, nonceLen int) error {
	if err := m.CredentialRequest.Verify(); err != nil {
		return err
	}

	if len(m.NonceU) != nonceLen {
		return errors.New("invalid server nonce")
	}

	// todo : verify if epku is valid

	return nil
}

func DeserializeKE1(input []byte, nonceLength, pointLen int) (*KE1, error) {
	creq, err := DeserializeCredentialRequest(input, pointLen)
	if err != nil {
		return nil, err
	}

	nonceU := input[pointLen:nonceLength]

	info, offset, err := internal.DecodeVector(input[pointLen+nonceLength:])
	if err != nil {
		return nil, err
	}

	offset = pointLen + nonceLength + offset
	epku := input[offset:]

	if len(epku) != pointLen {
		return nil, errors.New("invalid epku length")
	}

	return &KE1{
		CredentialRequest: creq,
		NonceU:            nonceU,
		ClientInfo:        info,
		EpkU:              epku,
	}, nil
}

type KE2 struct {
	*CredentialResponse
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Einfo  []byte `json:"i"`
	Mac    []byte `json:"m"`
}

func (m *KE2) Serialize() []byte {
	return utils.Concatenate(0, m.CredentialResponse.Serialize(), m.NonceS, m.EpkS, internal.EncodeVector(m.Einfo), m.Mac)
}

func (m *KE2) Verify(_ group.Group, nonceLen, macLength int) error {
	if err := m.CredentialResponse.Verify(); err != nil {
		return err
	}

	if len(m.NonceS) != nonceLen {
		return errors.New("invalid server nonce")
	}

	// todo : verify if epks is valid

	if len(m.Mac) != macLength {
		return errors.New("invalid mac length")
	}

	return nil
}

func DeserializeKE2(input []byte, nonceLength, pointLength, hashLen int) (*KE2, error) {
	cresp, offset, err := DeserializeCredentialResponse(input, pointLength, hashLen)
	if err != nil {
		return nil, err
	}

	nonceS := input[offset : offset+nonceLength]
	offset += nonceLength
	epks := input[offset : offset+pointLength]
	offset += pointLength

	einfo, length, err := internal.DecodeVector(input[offset:])
	if err != nil {
		return nil, err
	}

	mac := input[offset+length:]
	if len(mac) != hashLen {
		return nil, errors.New("invalid mac length")
	}

	return &KE2{
		CredentialResponse: cresp,
		NonceS:             nonceS,
		EpkS:               epks,
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

type KE3 struct {
	Mac []byte `json:"m"`
}

func (k KE3) Serialize() []byte {
	return k.Mac
}

func (m *KE3) Verify(macLength int) error {
	if len(m.Mac) != macLength {
		return errors.New("invalid mac length")
	}

	return nil
}

func DeserializeKe3(input []byte, hashSize int) (*KE3, error) {
	if len(input) != hashSize {
		return nil, errors.New("invalid mac length")
	}

	return &KE3{Mac: input}, nil
}
