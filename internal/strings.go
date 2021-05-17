// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

// These strings are the static tags and labels used throughout the protocol.
const (
	// Envelope tags.

	TagAuthKey    = "AuthKey"
	TagExportKey  = "ExportKey"
	TagMaskingKey = "MaskingKey"

	// Internal Mode tags.

	H2sDST = "OPAQUE-HashToScalar"
	SkDST  = "PrivateKey"

	// External Mode tags.

	TagPad = "Pad"

	// 3DH tags.

	Tag3DH        = "3DH"
	LabelPrefix   = "OPAQUE-"
	TagHandshake  = "HandshakeSecret"
	TagSession    = "SessionKey"
	TagMacServer  = "ServerMAC"
	TagMacClient  = "ClientMAC"
	TagEncServer  = "HandshakeKey"
	EncryptionTag = "EncryptionPad"

	// Client tags.

	TagCredentialResponsePad = "CredentialResponsePad"

	// Server tags.

	OprfKey = "OprfKey"
)
