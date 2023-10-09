// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package message

import (
	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal/encoding"
)

// CredentialRequest represents credential request message.
type CredentialRequest struct {
	BlindedMessage *group.Element `json:"blindedMessage"`
}

// NewCredentialRequest returns a populated CredentialRequest.
func NewCredentialRequest(message *group.Element) *CredentialRequest {
	return &CredentialRequest{
		BlindedMessage: message,
	}
}

// Serialize returns the byte encoding of CredentialRequest.
func (c *CredentialRequest) Serialize() []byte {
	return c.BlindedMessage.Encode()
}

// CredentialResponse represents credential response message.
type CredentialResponse struct {
	EvaluatedMessage *group.Element `json:"evaluatedMessage"`
	MaskingNonce     []byte         `json:"maskingNonce"`
	MaskedResponse   []byte         `json:"maskedResponse"`
}

// NewCredentialResponse returns a populated CredentialResponse.
func NewCredentialResponse(
	message *group.Element,
	nonce, response []byte,
) *CredentialResponse {
	return &CredentialResponse{
		EvaluatedMessage: message,
		MaskingNonce:     nonce,
		MaskedResponse:   response,
	}
}

// Serialize returns the byte encoding of CredentialResponse.
func (c *CredentialResponse) Serialize() []byte {
	return encoding.Concat3(c.EvaluatedMessage.Encode(), c.MaskingNonce, c.MaskedResponse)
}
