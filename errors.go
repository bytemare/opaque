package opaque

import "errors"

// TODO: centralise all errors here

// Configuration errors.
var (
	// ErrInvalidOPRFid indicates that the provided OPRF group identifier is invalid.
	ErrInvalidOPRFid = errors.New("invalid OPRF group id")

	// ErrInvalidKDFid indicates that the provided KDF identifier is invalid.
	ErrInvalidKDFid = errors.New("invalid KDF id")

	// ErrInvalidMACid indicates that the provided MAC identifier is invalid.
	ErrInvalidMACid = errors.New("invalid MAC id")

	// ErrInvalidHASHid indicates that the provided Hash identifier is invalid.
	ErrInvalidHASHid = errors.New("invalid Hash id")

	// ErrInvalidKSFid indicates that the provided KSF identifier is invalid.
	ErrInvalidKSFid = errors.New("invalid KSF id")

	// ErrInvalidAKEid indicates that the provided AKE group identifier is invalid.
	ErrInvalidAKEid = errors.New("invalid AKE group id")
)

// Server errors.
var (
	// ErrOPRFKeyNoSeed happens when no OPRF key seed is provided.
	ErrOPRFKeyNoSeed = errors.New("no OPRF key seed provided")
)

var (
	// ErrScalarNil indicates the provided scalar is nil.
	ErrScalarNil = errors.New("scalar is nil")

	// ErrScalarGroupMismatch indicates the provided scalar does not match the group.
	ErrScalarGroupMismatch = errors.New("scalar does not match the group")

	// ErrScalarZero indicates the provided scalar is zero.
	ErrScalarZero = errors.New("scalar is zero")

	// ErrElementNil indicates the provided element is nil.
	ErrElementNil = errors.New("element is nil")

	// ErrElementGroupMismatch indicates the provided element does not match the group.
	ErrElementGroupMismatch = errors.New("element does not match the group")

	// ErrElementIdentity indicates the provided element is the identity element (point at infinity).
	ErrElementIdentity = errors.New("element is the identity element")

	// ErrServerNilRegistrationRequest indicates the registration request is nil.
	ErrServerNilRegistrationRequest = errors.New("registration request is nil")

	// ErrServerNilKE1 indicates the ke1 message is nil or does not contain a credential request.
	ErrServerNilKE1 = errors.New("ke1 is nil or doesn't have a credential request")

	// Client.

	// ErrKe1Missing happens when GenerateKE3 is called and the client has no Ke1 in state and nonce if provided as an
	// option.
	ErrKe1Missing = errors.New("client state: missing KE1 message - call GenerateKE1 first")

	// ErrInvalidMaskedLength happens when the masked response length in KE2 is invalid.
	ErrInvalidMaskedLength = errors.New("invalid masked response length")

	// ErrClientAkeFailedHandshakeServerMac indicates a failed handshake because the server's MAC KE2 is could not be
	// verified. Execution of the connection must be aborted.
	ErrClientAkeFailedHandshakeServerMac = errors.New("3DH handshake failed: invalid server mac")

	// Deserializer

	// ErrInvalidMessageLength indicates the provided message length is invalid for the configuration.
	ErrInvalidMessageLength = errors.New("invalid message length for the configuration")

	// ErrInvalidBlindedData indicates the provided blinded data is not a valid point.
	ErrInvalidBlindedData = errors.New("blinded data is an invalid point")

	// ErrInvalidClientEPK indicates the provided ephemeral client public key is invalid.
	ErrInvalidClientEPK = errors.New("invalid ephemeral client public key")

	// ErrInvalidEvaluatedData indicates the provided evaluated data is not valid for the OPRF evaluation.
	ErrInvalidEvaluatedData = errors.New("invalid OPRF evaluation")

	// ErrInvalidServerEPK indicates the provided ephemeral server public key is invalid.
	ErrInvalidServerEPK = errors.New("invalid ephemeral server public key")

	// ErrInvalidServerPK indicates the provided server public key is invalid.
	ErrInvalidServerPK = errors.New("invalid server public key")

	// ErrInvalidClientPK indicates the provided client public key is invalid.
	ErrInvalidClientPK = errors.New("invalid client public key")

	// Misc.

	// ErrPrivateKeyZero indicates the provided private key is zero.
	ErrPrivateKeyZero = errors.New("private key is zero")

	// ErrPublicKeyIdentity indicates the provided public key is the identity element (point at infinity).
	ErrPublicKeyIdentity = errors.New("public key is identity element")
)
