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
	Pku      []byte            `json:"pku"`
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
	Data     []byte `json:"data"`
	Pks      []byte `json:"pks"`
	Envelope *envelope.Envelope `json:"env"`
}

func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, internal.EncodeVector(c.Pks), c.Envelope.Serialize())
}

func DeserializeCredentialResponse(input []byte, pointLen, hashSize int) (*CredentialResponse, int, error) {
	if len(input) < pointLen {
		return nil, 0, errors.New("credential response too short")
	}
	data := input[:pointLen]
	pks, pksLength := internal.DecodeVector(input[pointLen:])
	envU, envLength, err := envelope.DeserializeEnvelope(input[pointLen+pksLength:], hashSize)
	if err != nil {
		return nil, 0, err
	}
	offset := pointLen + pksLength + envLength

	return &CredentialResponse{
		Data:     data,
		Pks:      pks,
		Envelope: envU,
	}, offset, nil
}

// Protocol Messages

type ClientInit struct {
	Creq *CredentialRequest `json:"creq"`
	KE1  []byte `json:"ke1"`
}

func (m *ClientInit) Serialize() []byte {
	return append(m.Creq.Serialize(), m.KE1...)
}

func DeserializeClientInit(input []byte, pointLen int) (*ClientInit, error) {
	creq, err := DeserializeCredentialRequest(input, pointLen)
	if err != nil {
		return nil, err
	}

	return &ClientInit{
		Creq: creq,
		KE1:  input[pointLen:],
	}, nil
}

type ServerResponse struct {
	Cresp *CredentialResponse `json:"cres"`
	KE2   []byte `json:"ke2"`
}

func (m *ServerResponse) Serialize() []byte {
	return append(m.Cresp.Serialize(), m.KE2...)
}

func DeserializeServerResponse(input []byte, pointLen, hashLen int) (*ServerResponse, error) {
	cresp, offset, err := DeserializeCredentialResponse(input, pointLen, hashLen)
	if err != nil {
		return nil, err
	}

	ke2 := input[offset:]

	return &ServerResponse{
		Cresp: cresp,
		KE2:   ke2,
	}, nil
}

type ClientFinish struct {
	KE3 []byte `json:"ke3"`
}

func (m *ClientFinish) Serialize() []byte {
	return m.KE3
}
