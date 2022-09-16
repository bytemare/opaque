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
	"github.com/bytemare/opaque/internal/oprf"
)

// CredentialRequest represents credential request message.
type CredentialRequest struct {
	BlindedMessage *group.Element `json:"blindedMessage"`
	ciphersuite    oprf.Ciphersuite
}

// NewCredentialRequest returns a populated CredentialRequest.
func NewCredentialRequest(ciphersuite oprf.Ciphersuite, message *group.Element) *CredentialRequest {
	return &CredentialRequest{
		ciphersuite:    ciphersuite,
		BlindedMessage: message,
	}
}

// Serialize returns the byte encoding of CredentialRequest.
func (c *CredentialRequest) Serialize() []byte {
	return c.ciphersuite.SerializePoint(c.BlindedMessage)
}

// CredentialResponse represents credential response message.
type CredentialResponse struct {
	EvaluatedMessage *group.Element `json:"evaluatedMessage"`
	MaskingNonce     []byte         `json:"maskingNonce"`
	MaskedResponse   []byte         `json:"maskedResponse"`
	ciphersuite      oprf.Ciphersuite
}

// NewCredentialResponse returns a populated CredentialResponse.
func NewCredentialResponse(
	ciphersuite oprf.Ciphersuite,
	message *group.Element,
	nonce, response []byte,
) *CredentialResponse {
	return &CredentialResponse{
		ciphersuite:      ciphersuite,
		EvaluatedMessage: message,
		MaskingNonce:     nonce,
		MaskedResponse:   response,
	}
}

// Serialize returns the byte encoding of CredentialResponse.
func (c *CredentialResponse) Serialize() []byte {
	return encoding.Concat3(c.ciphersuite.SerializePoint(c.EvaluatedMessage), c.MaskingNonce, c.MaskedResponse)
}
