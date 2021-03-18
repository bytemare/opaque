package message

import (
	"errors"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type Deserializer struct {
	OPRFPointLength  ciphersuite.Identifier
	AkeGroup         ciphersuite.Identifier
	NonceLen, MacLen int
}

func (d *Deserializer) DeserializeRegistrationRequest(message []byte) (*RegistrationRequest, error) {
	r := DeserializeRegistrationRequest(message)
	if len(r.Data) != internal.PointLength(d.OPRFPointLength) {
		return nil, errors.New("invalid size")
	}

	return r, nil
}

func (d *Deserializer) DeserializeRegistrationResponse(message []byte) (*RegistrationResponse, error) {
	return DeserializeRegistrationResponse(message, internal.PointLength(d.OPRFPointLength), internal.PointLength(d.AkeGroup))
}

func (d *Deserializer) DeserializeRegistrationUpload(message []byte) (*RegistrationUpload, error) {
	return DeserializeRegistrationUpload(message, d.MacLen, internal.PointLength(d.AkeGroup), internal.ScalarLength(d.AkeGroup))
}

func (d *Deserializer) DeserializeCredentialRequest(message []byte) (*CredentialRequest, error) {
	if len(message) != internal.PointLength(d.OPRFPointLength) {
		return nil, errors.New("invalid message size")
	}

	return DeserializeCredentialRequest(message, internal.PointLength(d.OPRFPointLength)), nil
}

func (d *Deserializer) DeserializeCredentialResponse(message []byte) (*CredentialResponse, error) {
	c, _, err := DeserializeCredentialResponse(message, d.MacLen, internal.PointLength(d.OPRFPointLength), internal.PointLength(d.AkeGroup), internal.ScalarLength(d.AkeGroup))
	return c, err
}

func (d *Deserializer) DeserializeKE1(message []byte) (*KE1, error) {
	return DeserializeKE1(message, d.NonceLen, internal.PointLength(d.OPRFPointLength), internal.PointLength(d.AkeGroup))
}

func (d *Deserializer) DeserializeKE2(message []byte) (*KE2, error) {
	return DeserializeKE2(message, d.NonceLen, d.MacLen, internal.PointLength(d.OPRFPointLength), internal.PointLength(d.AkeGroup), internal.ScalarLength(d.AkeGroup))
}

func (d *Deserializer) DeserializeKE3(message []byte) (*KE3, error) {
	return DeserializeKE3(message, d.MacLen)
}

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

func DeserializeKE1(input []byte, nonceLength, oprfLen, akeLen int) (*KE1, error) {
	if len(input) != oprfLen+nonceLength+2+akeLen {
		return nil, errors.New("invalid message length")
	}

	creq := DeserializeCredentialRequest(input, oprfLen)
	nonceU := input[oprfLen : oprfLen+nonceLength]

	info, offset, err := internal.DecodeVector(input[oprfLen+nonceLength:])
	if err != nil {
		return nil, err
	}

	offset = oprfLen + nonceLength + offset
	epku := input[offset:]

	if len(epku) != akeLen {
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

func DeserializeKE2(input []byte, nonceLength, macLen, oprfLen, akeLen, scalarLen int) (*KE2, error) {
	cresp, offset, err := DeserializeCredentialResponse(input, macLen, oprfLen, akeLen, scalarLen)
	if err != nil {
		return nil, err
	}

	if len(input) < offset+nonceLength+akeLen+macLen {
		return nil, errors.New("invalid message length")
	}

	nonceS := input[offset : offset+nonceLength]
	offset += nonceLength
	epks := input[offset : offset+akeLen]
	offset += akeLen

	einfo, length, err := internal.DecodeVector(input[offset:])
	if err != nil {
		return nil, err
	}

	mac := input[offset+length:]

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

func DeserializeKE3(input []byte, macLen int) (*KE3, error) {
	if len(input) != macLen {
		return nil, errors.New("invalid mac length")
	}

	return &KE3{Mac: input}, nil
}
