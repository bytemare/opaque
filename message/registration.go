// Package message provides message structures for the OPAQUE protocol.
package message

import (
	"github.com/bytemare/cryptotools/utils"
)

// RegistrationRequest is the first message of the registration flow, created by the client and sent to the server.
type RegistrationRequest struct {
	Data []byte `json:"data"`
}

// Serialize returns the byte encoding of RegistrationRequest.
func (r *RegistrationRequest) Serialize() []byte {
	return r.Data
}

// RegistrationResponse is the second message of the registration flow, created by the server and sent to the client.
type RegistrationResponse struct {
	Data []byte `json:"data"`
	Pks  []byte `json:"pks"`
}

// Serialize returns the byte encoding of RegistrationResponse.
func (r *RegistrationResponse) Serialize() []byte {
	return utils.Concatenate(len(r.Data)+len(r.Pks), r.Data, r.Pks)
}

// RegistrationUpload represents the client record sent as the last registration message by the client to the server.
type RegistrationUpload struct {
	PublicKey  []byte `json:"pku"`
	MaskingKey []byte `json:"msk"`
	Envelope   []byte `json:"env"`
}

// Serialize returns the byte encoding of RegistrationUpload.
func (r *RegistrationUpload) Serialize() []byte {
	return utils.Concatenate(0, r.PublicKey, r.MaskingKey, r.Envelope)
}
