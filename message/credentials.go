package message

import (
	"errors"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
)

// Registration

type RegistrationRequest struct {
	Data []byte `json:"data"`
}

func (r *RegistrationRequest) Serialize() []byte {
	return r.Data
}

type RegistrationResponse struct {
	Data []byte `json:"data"`
	Pks  []byte `json:"pks"`
}

func (r *RegistrationResponse) Serialize() []byte {
	return append(r.Data, internal.EncodeVector(r.Pks)...)
}

type RegistrationUpload struct {
	Envelope *envelope.Envelope `json:"env"`
	Pku      []byte             `json:"pku"`
}

func (r *RegistrationUpload) Serialize() []byte {
	return append(internal.EncodeVector(r.Pku), r.Envelope.Serialize()...)
}

// Authentication

type CredentialRequest struct {
	Data []byte `json:"data"`
}

func (c *CredentialRequest) Serialize() []byte {
	return c.Data
}

func DeserializeCredentialRequest(input []byte, pointLen int) (*CredentialRequest, error) {
	if len(input) <= pointLen {
		return nil, errors.New("malformed credential request")
	}
	return &CredentialRequest{input[:pointLen]}, nil
}

type CredentialResponse struct {
	Data     []byte             `json:"data"`
	Pks      []byte             `json:"pks"`
	Envelope *envelope.Envelope `json:"env"`
}

func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, internal.EncodeVector(c.Pks), c.Envelope.Serialize())
}

func DeserializeCredentialResponse(input []byte, pointLen, hashSize int) (response *CredentialResponse, offset int, err error) {
	if len(input) < pointLen {
		return nil, 0, errors.New("credential response too short")
	}

	data := input[:pointLen]

	pks, pksLength, err := internal.DecodeVector(input[pointLen:])
	if err != nil {
		return nil, 0, err
	}

	envU, envLength, err := envelope.DeserializeEnvelope(input[pointLen+pksLength:], hashSize)
	if err != nil {
		return nil, 0, err
	}
	offset = pointLen + pksLength + envLength

	return &CredentialResponse{
		Data:     data,
		Pks:      pks,
		Envelope: envU,
	}, offset, nil
}
