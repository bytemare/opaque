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
	return utils.Concatenate(len(r.Data)+len(r.Pks), r.Data, r.Pks)
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
	Pku        []byte             `json:"pku"`
	MaskingKey []byte             `json:"msk"`
	Envelope   *envelope.Envelope `json:"env"`
}

func (r *RegistrationUpload) Serialize() []byte {
	return utils.Concatenate(0, r.Pku, r.MaskingKey, r.Envelope.Serialize())
}

func DeserializeRegistrationUpload(input []byte, hashLen, macLen, pointLen, scalarLen, nonceLen, envLen int) (*RegistrationUpload, error) {
	l := len(input)
	if l != pointLen+hashLen+envLen {
		return nil, errors.New("invalid message length")
	}

	pku := input[:pointLen]
	maskingKey := input[pointLen : pointLen+hashLen]

	env, _, err := envelope.DeserializeEnvelope(input[pointLen+hashLen:], nonceLen, macLen, scalarLen)
	if err != nil {
		return nil, err
	}

	return &RegistrationUpload{
		Pku:        pku,
		MaskingKey: maskingKey,
		Envelope:   env,
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
	Data           []byte `json:"data"`
	MaskingNonce   []byte `json:"mn"`
	MaskedResponse []byte `json:"mr"`
}

func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, c.MaskingNonce, c.MaskedResponse)
}

func DeserializeCredentialResponse(input []byte, oprfLen, nonceLen, akeLen, envLen int) (response *CredentialResponse, offset int, err error) {
	if len(input) <= oprfLen+nonceLen+akeLen+envLen {
		return nil, 0, errors.New("invalid CredentialResponse length")
	}

	return &CredentialResponse{
		Data:           input[:oprfLen],
		MaskingNonce:   input[oprfLen : oprfLen+nonceLen],
		MaskedResponse: input[oprfLen+nonceLen : oprfLen+nonceLen+akeLen+envLen],
	}, oprfLen + nonceLen + akeLen + envLen, nil
}
