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
	// OPRF tags.

	// OPRF is a string explicitly stating the version name.
	OPRF = "VOPRF07-"

	// OPRFPrefix is the DST prefix to use for HashToGroup operations.
	OPRFPrefix = "HashToGroup-"

	// OPRFFinalize is the DST suffix used in the client transcript.
	OPRFFinalize = "Finalize-"

	// Envelope tags.

	// AuthKey is the envelope's MAC key's KDF dst.
	AuthKey = "AuthKey"

	// ExportKey is the export key's KDF dst.
	ExportKey = "ExportKey"

	// MaskingKey is the masking key's creation KDF dst.
	MaskingKey = "MaskingKey"

	// DerivePrivateKey is the client's internal mode private key hash-to-scalar dst.
	DerivePrivateKey = "OPAQUE-DeriveAuthKeyPair"

	// ExpandPrivateKey is the client's internal mode private key seed KDF dst.
	ExpandPrivateKey = "PrivateKey"

	// EncryptionPad is the external mode's encryption key KDF dst.
	EncryptionPad = "Pad"

	// 3DH tags.

	// VersionTag indicates the protocol RFC identifier for the AKE transcript prefix.
	VersionTag = "RFCXXXX"

	// LabelPrefix is the 3DH secret KDF dst prefix.
	LabelPrefix = "OPAQUE-"

	// Handshake is the 3DH HandshakeSecret dst.
	Handshake = "HandshakeSecret"

	// SessionKey is the 3DH session secret dst.
	SessionKey = "SessionKey"

	// MacServer is 3DH server's MAC key KDF dst.
	MacServer = "ServerMAC"

	// MacClient is 3DH server's MAC key KDF dst.
	MacClient = "ClientMAC"

	// Client tags.

	// CredentialResponsePad is the masking keys KDF dst to expand to the input.
	CredentialResponsePad = "CredentialResponsePad"

	// Server tags.

	// ExpandOPRF is the server's OPRF key seed KDF dst.
	ExpandOPRF = "OprfKey"

	// DeriveKeyPair is the server's OPRF hash-to-scalar dst.
	DeriveKeyPair = "OPAQUE-DeriveKeyPair"
)
