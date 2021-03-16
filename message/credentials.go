package message

import (
	"errors"
	"github.com/bytemare/opaque/core/envelope"

	"github.com/bytemare/cryptotools/utils"
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

func DeserializeRegistrationResponse(input []byte, pointLen int) (*RegistrationResponse, error) {
	if len(input) != 2*pointLen {
		return nil, errors.New("invalid size")
	}

	return &RegistrationResponse{
		Data: input[:pointLen],
		Pks:  input[pointLen:],
	}, nil
}

type RegistrationUpload struct {
	Envelope *envelope.Envelope `json:"env"`
	Pku      []byte             `json:"pku"`
}

func (r *RegistrationUpload) Serialize() []byte {
	return append(r.Pku, r.Envelope.Serialize()...)
}

// Authentication

type CredentialRequest struct {
	Data []byte `json:"data"`
}

func (c *CredentialRequest) Serialize() []byte {
	return c.Data
}

func (c *CredentialRequest) Verify() error {
	// todo : verify data is of sufficient length

	return nil
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
	Pkc      []byte             `json:"pkc"`
	Envelope *envelope.Envelope `json:"env"`
}

func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, c.Pkc, c.Pks, c.Envelope.Serialize())
}

func (c *CredentialResponse) Verify() error {
	// todo : verify data is of sufficient length

	// todo : verify epks is valid

	// todo : verify envelope is of sufficient length

	return nil
}

func DeserializeCredentialResponse(input []byte, Npk, Nm int) (response *CredentialResponse, offset int, err error) {
	if len(input) < 2*Npk {
		return nil, 0, errors.New("credential response too short")
	}

	data := input[:Npk]
	pks := input[Npk : 2*Npk]
	pkc := input[2*Npk : 3*Npk]

	envU, err := envelope.DeserializeEnvelope(input[2*Npk:], Nm)
	if err != nil {
		return nil, 0, err
	}

	offset = len(input)

	return &CredentialResponse{
		Data:     data,
		Pks:      pks,
		Pkc:      pkc,
		Envelope: envU,
	}, offset, nil
}
