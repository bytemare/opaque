// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package message provides message structures for the OPAQUE protocol.
package message

import (
	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal/encoding"
)

// KE1 is the first message of the login flow, created by the client and sent to the server.
type KE1 struct {
	*CredentialRequest
	ClientPublicKeyshare *ecc.Element `json:"clientPublicKeyshare"`
	ClientNonce          []byte       `json:"clientNonce"`
}

// Serialize returns the byte encoding of KE1.
func (m *KE1) Serialize() []byte {
	return encoding.Concat3(m.CredentialRequest.Serialize(), m.ClientNonce, m.ClientPublicKeyshare.Encode())
}

// KE2 is the second message of the login flow, created by the server and sent to the client.
type KE2 struct {
	*CredentialResponse
	ServerPublicKeyshare *ecc.Element `json:"serverPublicKeyshare"`
	ServerNonce          []byte       `json:"serverNonce"`
	ServerMac            []byte       `json:"serverMac"`
}

// Serialize returns the byte encoding of KE2.
func (m *KE2) Serialize() []byte {
	return encoding.Concat(
		m.CredentialResponse.Serialize(),
		encoding.Concat3(m.ServerNonce, m.ServerPublicKeyshare.Encode(), m.ServerMac),
	)
}

// KE3 is the third and last message of the login flow, created by the client and sent to the server.
type KE3 struct {
	ClientMac []byte `json:"clientMac"`
}

// Serialize returns the byte encoding of KE3.
func (k KE3) Serialize() []byte {
	return k.ClientMac
}
