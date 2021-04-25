package internal

const (
	// Envelope

	TagAuthKey    = "AuthKey"
	TagExportKey  = "ExportKey"
	TagMaskingKey = "MaskingKey"

	// Internal Mode

	H2sDST = "OPAQUE-HashToScalar"
	SkDST  = "PrivateKey"

	// External Mode

	TagPad = "Pad"

	// 3DH

	Tag3DH        = "3DH"
	LabelPrefix   = "OPAQUE-"
	TagHandshake  = "HandshakeSecret"
	TagSession    = "SessionKey"
	TagMacServer  = "ServerMAC"
	TagMacClient  = "ClientMAC"
	TagEncServer  = "HandshakeKey"
	EncryptionTag = "EncryptionPad"

	// Client

	TagCredentialResponsePad = "CredentialResponsePad"

	// Server

	OprfKey = "OprfKey"
)
