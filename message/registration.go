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
	"github.com/bytemare/opaque/internal/oprf"
)

// RegistrationRequest is the first message of the registration flow, created by the client and sent to the server.
type RegistrationRequest struct {
	C    oprf.Ciphersuite
	Data *group.Point `json:"data"`
}

// Serialize returns the byte encoding of RegistrationRequest.
func (r *RegistrationRequest) Serialize() []byte {
	return r.C.SerializePoint(r.Data)
}

// RegistrationResponse is the second message of the registration flow, created by the server and sent to the client.
type RegistrationResponse struct {
	C    oprf.Ciphersuite
	G    group.Group
	Data *group.Point `json:"data"`
	Pks  *group.Point `json:"pks"`
}

// Serialize returns the byte encoding of RegistrationResponse.
func (r *RegistrationResponse) Serialize() []byte {
	return encoding.Concat(r.C.SerializePoint(r.Data), encoding.SerializePoint(r.Pks, r.G))
}

// RegistrationRecord represents the client record sent as the last registration message by the client to the server.
type RegistrationRecord struct {
	G          group.Group
	PublicKey  *group.Point `json:"pku"`
	MaskingKey []byte       `json:"msk"`
	Envelope   []byte       `json:"env"`
}

// Serialize returns the byte encoding of RegistrationRecord.
func (r *RegistrationRecord) Serialize() []byte {
	return encoding.Concat3(encoding.SerializePoint(r.PublicKey, r.G), r.MaskingKey, r.Envelope)
}
