// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package tag provides the static tag strings to OPAQUE.
package tag

// These strings are the static tags and labels used throughout the protocol.
const (
	// Envelope tags.

	AuthKey    = "AuthKey"
	ExportKey  = "ExportKey"
	MaskingKey = "MaskingKey"

	// Internal Mode tags.

	H2sDST       = "OPAQUE-HashToScalar"
	SecretKeyDST = "PrivateKey"

	// External Mode tags.

	Pad = "Pad"

	// 3DH tags.

	VersionTag  = "RFCXXXX"
	LabelPrefix = "OPAQUE-"
	Handshake   = "HandshakeSecret"
	Session     = "SessionKey"
	MacServer   = "ServerMAC"
	MacClient   = "ClientMAC"

	// Client tags.

	CredentialResponsePad = "CredentialResponsePad"

	// Server tags.

	OprfKey       = "OprfKey"
	DeriveKeyPair = "OPAQUE-DeriveKeyPair"
)
