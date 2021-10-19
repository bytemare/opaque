// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package message provides message structures for the OPAQUE protocol.
package message

import (
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/message"
)

// KE1 is the first message of the login flow, created by the client and sent to the server.
type KE1 struct {
	G group.Group
	*message.CredentialRequest
	NonceU []byte       `json:"n"`
	EpkU   *group.Point `json:"e"`
}

// Serialize returns the byte encoding of KE1.
func (m *KE1) Serialize() []byte {
	return encoding.Concat3(m.CredentialRequest.Serialize(), m.NonceU, encoding.SerializePoint(m.EpkU, m.G))
}

// KE2 is the second message of the login flow, created by the server and sent to the client.
type KE2 struct {
	G group.Group
	*message.CredentialResponse
	NonceS []byte       `json:"n"`
	EpkS   *group.Point `json:"e"`
	Mac    []byte       `json:"m"`
}

// Serialize returns the byte encoding of KE2.
func (m *KE2) Serialize() []byte {
	return encoding.Concat(m.CredentialResponse.Serialize(), encoding.Concat3(m.NonceS, encoding.SerializePoint(m.EpkS, m.G), m.Mac))
}

// KE3 is the third and last message of the login flow, created by the client and sent to the server.
type KE3 struct {
	Mac []byte `json:"m"`
}

// Serialize returns the byte encoding of KE3.
func (k KE3) Serialize() []byte {
	return k.Mac
}
