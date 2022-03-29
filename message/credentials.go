// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package message provides the internal credential recovery messages.
package message

import (
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
)

// CredentialRequest represents credential request message.
type CredentialRequest struct {
	C              oprf.Ciphersuite
	BlindedMessage *group.Point `json:"blinded_message"`
}

// Serialize returns the byte encoding of CredentialRequest.
func (c *CredentialRequest) Serialize() []byte {
	return c.C.SerializePoint(c.BlindedMessage)
}

// CredentialResponse represents credential response message.
type CredentialResponse struct {
	C                oprf.Ciphersuite
	EvaluatedMessage *group.Point `json:"evaluated_message"`
	MaskingNonce     []byte       `json:"masking_nonce"`
	MaskedResponse   []byte       `json:"masked_response"`
}

// Serialize returns the byte encoding of CredentialResponse.
func (c *CredentialResponse) Serialize() []byte {
	return encoding.Concat3(c.C.SerializePoint(c.EvaluatedMessage), c.MaskingNonce, c.MaskedResponse)
}
