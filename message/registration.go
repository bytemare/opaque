// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package message

import (
	group "github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal/encoding"
)

// RegistrationRequest is the first message of the registration flow, created by the client and sent to the server.
type RegistrationRequest struct {
	BlindedMessage *group.Element `json:"blindedMessage"`
}

// Serialize returns the byte encoding of RegistrationRequest.
func (r *RegistrationRequest) Serialize() []byte {
	return r.BlindedMessage.Encode()
}

// RegistrationResponse is the second message of the registration flow, created by the server and sent to the client.
type RegistrationResponse struct {
	EvaluatedMessage *group.Element `json:"evaluatedMessage"`
	Pks              *group.Element `json:"serverPublicKey"`
}

// Serialize returns the byte encoding of RegistrationResponse.
func (r *RegistrationResponse) Serialize() []byte {
	return encoding.Concat(r.EvaluatedMessage.Encode(), r.Pks.Encode())
}

// RegistrationRecord represents the client record sent as the last registration message by the client to the server.
type RegistrationRecord struct {
	PublicKey  *group.Element `json:"clientPublicKey"`
	MaskingKey []byte         `json:"maskingKey"`
	Envelope   []byte         `json:"envelope"`
}

// Serialize returns the byte encoding of RegistrationRecord.
func (r *RegistrationRecord) Serialize() []byte {
	return encoding.Concat3(r.PublicKey.Encode(), r.MaskingKey, r.Envelope)
}
