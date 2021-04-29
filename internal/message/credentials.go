// Package message provides the internal credential recovery messages.
package message

import "github.com/bytemare/cryptotools/utils"

type CredentialRequest struct {
	Data []byte `json:"data"`
}

// Serialize returns the byte encoding of CredentialRequest.
func (c *CredentialRequest) Serialize() []byte {
	return c.Data
}

type CredentialResponse struct {
	Data           []byte `json:"data"`
	MaskingNonce   []byte `json:"mn"`
	MaskedResponse []byte `json:"mr"`
}

// Serialize returns the byte encoding of CredentialResponse.
func (c *CredentialResponse) Serialize() []byte {
	return utils.Concatenate(0, c.Data, c.MaskingNonce, c.MaskedResponse)
}
