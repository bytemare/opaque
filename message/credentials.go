package message

import (
	"errors"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/core/envelope"
)

// Registration

type RegistrationRequest struct {
	Data []byte `json:"data"`
}

func (r *RegistrationRequest) Serialize() []byte {
	return r.Data
}

func DeserializeRegistrationRequest(input []byte) *RegistrationRequest {
	return &RegistrationRequest{input}
}

type RegistrationResponse struct {
	Data []byte `json:"data"`
	Pks  []byte `json:"pks"`
}

func (r *RegistrationResponse) Serialize() []byte {
	return append(r.Data, r.Pks...)
}

func DeserializeRegistrationResponse(input []byte, oprfPointLen, akepointLen int) (*RegistrationResponse, error) {
	if len(input) != oprfPointLen+akepointLen {
		return nil, errors.New("invalid size")
	}

	return &RegistrationResponse{
		Data: input[:oprfPointLen],
		Pks:  input[oprfPointLen:],
	}, nil
}

type RegistrationUpload struct {
	Pku      []byte             `json:"pku"`
	Envelope *envelope.Envelope `json:"env"`
}

func (r *RegistrationUpload) Serialize() []byte {
	return append(r.Pku, r.Envelope.Serialize()...)
}

func DeserializeRegistrationUpload(input []byte, macLen, pointLen, scalarLen int) (*RegistrationUpload, error) {
	l := len(input)
	if l <= pointLen {
		return nil, errors.New("invalid message length")
	}

	pku := input[:pointLen]

	env, _, err := envelope.DeserializeEnvelope(input[pointLen:], macLen, scalarLen)
	if err != nil {
		return nil, err
	}

	return &RegistrationUpload{
		Envelope: env,
		Pku:      pku,
	}, nil
}

// Authentication

type CredentialRequest struct {
	Data []byte `json:"data"`
}

func (c *CredentialRequest) Serialize() []byte {
	return c.Data
}

func DeserializeCredentialRequest(input []byte, pointLen int) *CredentialRequest {
	return &CredentialRequest{input[:pointLen]}
}

type CredentialResponse struct {
	Data     []byte             `json:"data"`
	Pks      []byte             `json:"pks"`
	Pkc      []byte             `json:"pkc"`
	Envelope *envelope.Envelope `json:"env"`
}

func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, c.Pks, c.Pkc, c.Envelope.Serialize())
}

func DeserializeCredentialResponse(input []byte, macLen, oprfLen, akeLen, scalarLen int) (response *CredentialResponse, offset int, err error) {
	if len(input) < 2*akeLen+oprfLen {
		return nil, 0, errors.New("credential response too short")
	}

	data := input[:oprfLen]
	pks := input[oprfLen : oprfLen+akeLen]
	pkc := input[oprfLen+akeLen : oprfLen+akeLen+akeLen]

	envU, envLen, err := envelope.DeserializeEnvelope(input[oprfLen+akeLen+akeLen:], macLen, scalarLen)
	if err != nil {
		return nil, 0, err
	}

	offset = oprfLen + akeLen + akeLen + envLen

	return &CredentialResponse{
		Data:     data,
		Pks:      pks,
		Pkc:      pkc,
		Envelope: envU,
	}, offset, nil
}
