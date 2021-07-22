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
	"github.com/bytemare/opaque/internal/encoding"
)

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
	return encoding.Concat3(c.Data, c.MaskingNonce, c.MaskedResponse)
}
