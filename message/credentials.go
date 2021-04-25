package message

import (
	"github.com/bytemare/cryptotools/utils"
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
	return utils.Concatenate(len(r.Data)+len(r.Pks), r.Data, r.Pks)
}

type RegistrationUpload struct {
	PublicKey  []byte `json:"pku"`
	MaskingKey []byte `json:"msk"`
	Envelope   []byte `json:"env"`
}

func (r *RegistrationUpload) Serialize() []byte {
	return utils.Concatenate(0, r.PublicKey, r.MaskingKey, r.Envelope)
}

// Authentication

type CredentialRequest struct {
	Data []byte `json:"data"`
}

func (c *CredentialRequest) Serialize() []byte {
	return c.Data
}

type CredentialResponse struct {
	Data           []byte `json:"data"`
	MaskingNonce   []byte `json:"mn"`
	MaskedResponse []byte `json:"mr"`
}

func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, c.MaskingNonce, c.MaskedResponse)
}
