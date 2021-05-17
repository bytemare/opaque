// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package message provides message structures for the OPAQUE protocol.
package message

import (
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/message"
)

// KE1 is the first message of the login flow, created by the client and sent to the server.
type KE1 struct {
	*message.CredentialRequest
	NonceU     []byte `json:"n"`
	ClientInfo []byte `json:"i"`
	EpkU       []byte `json:"e"`
}

// Serialize returns the byte encoding of KE1.
func (m *KE1) Serialize() []byte {
	return utils.Concatenate(0, m.CredentialRequest.Serialize(), m.NonceU, encoding.EncodeVector(m.ClientInfo), m.EpkU)
}

// KE2 is the second message of the login flow, created by the server and sent to the client.
type KE2 struct {
	*message.CredentialResponse
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Einfo  []byte `json:"i"`
	Mac    []byte `json:"m"`
}

// Serialize returns the byte encoding of KE2.
func (m *KE2) Serialize() []byte {
	return utils.Concatenate(0, m.CredentialResponse.Serialize(), m.NonceS, m.EpkS, encoding.EncodeVector(m.Einfo), m.Mac)
}

// KE3 is the third and last message of the login flow, created by the client and sent to the server.
type KE3 struct {
	Mac []byte `json:"m"`
}

// Serialize returns the byte encoding of KE3.
func (k KE3) Serialize() []byte {
	return k.Mac
}
