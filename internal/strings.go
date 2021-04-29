// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

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
