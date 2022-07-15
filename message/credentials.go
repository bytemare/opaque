// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package message

import (
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
)

// CredentialRequest represents credential request message.
type CredentialRequest struct {
	ciphersuite    oprf.Ciphersuite
	BlindedMessage *group.Point `json:"blinded_message"`
}

func NewCredentialRequest(ciphersuite oprf.Ciphersuite, message *group.Point) *CredentialRequest {
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
	ciphersuite      oprf.Ciphersuite
	EvaluatedMessage *group.Point `json:"evaluated_message"`
	MaskingNonce     []byte       `json:"masking_nonce"`
	MaskedResponse   []byte       `json:"masked_response"`
}

func NewCredentialResponse(
	ciphersuite oprf.Ciphersuite,
	message *group.Point,
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
