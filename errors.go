// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"errors"
	"fmt"
)

/*
Errors in the OPAQUE library.

Types of errors:
- Configuration errors: errors related to the configuration of the OPAQUE protocol.
- ServerKeyMaterial errors: errors related to the server's key material.
- ClientRecord errors: errors related to the client record.
- Option errors: errors related to the optional client and server parameters.
- Registration errors: errors related to the registration process.
- Login errors: errors related to the login process.
- Deserialization errors: errors related to the deserialization of messages.

TODO:
	- The error list down below may not be correctly ordered, too verbose, and some errors may be redundant or not useful: find a way to make this user friendly and actionable.
	- verify all errors have been tested against: maybe add a lint or check?
*/

// Authentication errors: upon error, the protocol must be aborted and the keys must not be used.
var (
	// ErrAuthentication indicates that the authentication process failed.
	ErrAuthentication = errors.New("authentication error")

	// ErrAuthenticationInvalidServerPublicKey indicates the authentication process failed because the server's public
	// key in the KE2 message is invalid.
	ErrAuthenticationInvalidServerPublicKey = prefixError(ErrAuthentication, ErrInvalidServerPK)

	// ErrServerAuthentication indicates a failed handshake because the server's MAC KE2 could not be
	// verified. Execution of the connection must be aborted.
	ErrServerAuthentication = errors.New("failed to authenticate server: invalid server mac")

	// ErrClientAuthentication indicates that the MAC contained in the KE3 message is not valid in the given session.
	ErrClientAuthentication = errors.New("failed to authenticate client: invalid client mac")

	// ErrAuthenticationClientKey indicates the authentication process failed because the client's private key could not
	// be recovered.
	ErrAuthenticationClientKey = fmt.Errorf("%w: failed to recover the client's private key", ErrAuthentication)
)

// Configuration errors.
var (
	// ErrConfiguration indicates that the configuration is invalid.
	ErrConfiguration = errors.New("invalid configuration")

	// ErrInvalidOPRFid indicates that the provided OPRF group identifier is invalid.
	ErrInvalidOPRFid = fmt.Errorf("%w: invalid OPRF group id", ErrConfiguration)

	// ErrInvalidKDFid indicates that the provided KDF identifier is invalid.
	ErrInvalidKDFid = fmt.Errorf("%w: invalid KDF id", ErrConfiguration)

	// ErrInvalidMACid indicates that the provided MAC identifier is invalid.
	ErrInvalidMACid = fmt.Errorf("%w: invalid MAC id", ErrConfiguration)

	// ErrInvalidHASHid indicates that the provided Hash identifier is invalid.
	ErrInvalidHASHid = fmt.Errorf("%w: invalid Hash id", ErrConfiguration)

	// ErrInvalidKSFid indicates that the provided KSF identifier is invalid.
	ErrInvalidKSFid = fmt.Errorf("%w: invalid KSF id", ErrConfiguration)

	// ErrInvalidAKEid indicates that the provided AKE group identifier is invalid.
	ErrInvalidAKEid = fmt.Errorf("%w: invalid AKE group id", ErrConfiguration)
)

// ServerKeyMaterial errors.
var (
	// ErrServerKeyMaterial indicates that the server's key material is invalid.
	ErrServerKeyMaterial = errors.New("invalid server key material")

	// ErrServerKeyMaterialDecoding indicates that the server's key material could not be decoded.
	ErrServerKeyMaterialDecoding = prefixError(ErrServerKeyMaterial, ErrDecoding)

	// ErrServerKeyMaterialInvalidEncodingLength indicates that the length of the provided encoding is not valid
	// for the server's key material in the configuration.
	ErrServerKeyMaterialInvalidEncodingLength = prefixError(ErrServerKeyMaterialDecoding, ErrInvalidEncodingLength)

	// ErrServerKeyMaterialInvalidGroupEncoding indicates that the group encoding in the server's key material is not
	// valid or the group is not available.
	ErrServerKeyMaterialInvalidGroupEncoding = fmt.Errorf("%w: invalid group", ErrServerKeyMaterialDecoding)

	// ErrServerKeyMaterialInvalidPrivateKeyEncoding indicates that the private key encoding in the server's key material
	// is not valid.
	ErrServerKeyMaterialInvalidPrivateKeyEncoding = prefixError(ErrServerKeyMaterialDecoding, ErrInvalidPrivateKey)

	// ErrServerKeyMaterialPrivateKeyZero indicates that the private key in the server's key material is zero.
	ErrServerKeyMaterialPrivateKeyZero = fmt.Errorf(
		"%w: %w: %w",
		ErrServerKeyMaterialDecoding,
		ErrInvalidPrivateKey,
		ErrScalarZero,
	)

	// ErrServerKeyMaterialDecodingEmptyHex indicates that the server's key material decoding failed because the
	// provided hex string is empty.
	ErrServerKeyMaterialDecodingEmptyHex = fmt.Errorf("%w: empty hex string", ErrServerKeyMaterialDecoding)

	// ErrServerKeyMaterialNil indicates that the server's key material has not been set.
	ErrServerKeyMaterialNil = fmt.Errorf(
		"%w: key material not set - use SetKeyMaterial() to set and validate values",
		ErrServerKeyMaterial,
	)

	// ErrServerKeyMaterialInvalidOPRFSeedLength indicates that the OPRF seed is not of right length.
	ErrServerKeyMaterialInvalidOPRFSeedLength = fmt.Errorf(
		"%w: invalid OPRF seed length (must be equal to the hash output length)",
		ErrServerKeyMaterial,
	)

	// ErrServerKeymaterialOPRFKeyNoSeed happens when no OPRF key seed is provided.
	ErrServerKeymaterialOPRFKeyNoSeed = fmt.Errorf("%w: no OPRF key seed provided", ErrServerKeyMaterial)
)

// Server options errors.
var (
	// ErrServerOptions indicates that the provided server options are invalid.
	ErrServerOptions = errors.New("invalid server options")

	// ErrServerOptionsClientOPRFKey indicates the provided OPRF key for the client is invalid. Note that providing this
	// key is not required. Use this option at your own risk.
	ErrServerOptionsClientOPRFKey = fmt.Errorf("%w: the provided OPRF key for the client is invalid", ErrServerOptions)

	// ErrServerInvalidPublicKeyLength indicates that the length of the server public key is not valid for the configuration.
	ErrServerInvalidPublicKeyLength = errors.New("the provided server public key is not a valid encoding for the " +
		"configuration")

	// ErrServerOptionsMaskingNonceLength indicates that the MaskingNonce provided in the ServerOptions does not have
	// the required length for the configuration. Note that providing a nonce is not required, as a new nonce will be
	// generated internally at each call.
	ErrServerOptionsMaskingNonceLength = errors.New(
		"the provided masking key does not have the required length for the configuration",
	)
)

// Server errors.
var (
	// ErrServerRegistrationRequestBlindedMessage indicates that the blinded message in the registration request is invalid.
	ErrServerRegistrationRequestBlindedMessage = prefixError(ErrInvalidRegistrationRequest, ErrInvalidBlindedMessage)

	// ErrServerKE1Incomplete indicates that the KE1 message is incomplete or has nil fields.
	ErrServerKE1Incomplete = fmt.Errorf("%w: nil or missing fields", ErrInvalidKE1)

	// ErrServerKE1BlindedMessage indicates that the blinded message in the KE1 message is invalid.
	ErrServerKE1BlindedMessage = prefixError(ErrInvalidKE1, ErrInvalidBlindedMessage)

	// ErrServerKE1InvalidClientKeyShare indicates that the client public key share in the KE1 message is invalid.
	ErrServerKE1InvalidClientKeyShare = prefixError(ErrInvalidKE1, ErrInvalidClientKeyShare)

	// ErrNoCredentialIdentifier indicates no credential identifier has been provided.
	ErrNoCredentialIdentifier = errors.New("no credential identifier provided")
)

// ClientRecord errors.
var (
	// ErrInvalidClientRecord indicates that the client record is invalid.
	ErrInvalidClientRecord = errors.New("invalid client record")

	// ErrClientRecordNil indicates that the client record is nil.
	ErrClientRecordNil = fmt.Errorf("%w: client record is nil", ErrInvalidClientRecord)

	// ErrClientRecordNilRegistrationRecord indicates that the registration record contained in the client record is nil.
	ErrClientRecordNilRegistrationRecord = fmt.Errorf("%w: registration record is nil", ErrInvalidClientRecord)

	// ErrClientRecordNilPubKey indicates that the client's public key is nil.
	ErrClientRecordNilPubKey = fmt.Errorf("%w: client public key is nil", ErrInvalidClientRecord)

	// ErrClientRecordPublicKeyGroupMismatch indicates that the client's public key group does not match the
	// configuration's group.
	ErrClientRecordPublicKeyGroupMismatch = fmt.Errorf(
		"%w: client public key group does not match the configuration's group",
		ErrInvalidClientRecord,
	)

	// ErrClientRecordInvalidEnvelopeLength indicates the envelope contained in the record is of invalid length.
	ErrClientRecordInvalidEnvelopeLength = fmt.Errorf(
		"%w: envelope: %w",
		ErrInvalidClientRecord,
		ErrInvalidEncodingLength,
	)

	// ErrClientRecordInvalidMaskingKeyLength indicates that the length of the masking key contained in the record
	// is not valid.
	ErrClientRecordInvalidMaskingKeyLength = fmt.Errorf("%w: invalid masking key length", ErrInvalidClientRecord)

	// ErrClientRecordPublicKeyIdentity indicates that the client's public key is the identity element (point at infinity).
	ErrClientRecordPublicKeyIdentity = fmt.Errorf("%w: client public key is the identity element (point at infinity)",
		ErrInvalidClientRecord)
)

// Client errors.
var (
	// ErrClientPreviousBlind indicates that the client state already contains an OPRF blind, which indicates a prior run
	// of the protocol.
	ErrClientPreviousBlind = errors.New("an OPRF blind already exists in the client state, indicating a prior run" +
		"of the protocol. Use a new client instance or clear the state with ClearState() before starting a new run")

	// ErrClientKE2Invalid indicates that the KE2 message is invalid.
	ErrClientKE2Invalid = errors.New("invalid KE2 message")

	// ErrClientKE2Nil indicates that the KE2 message is nil.
	ErrClientKE2Nil = fmt.Errorf("%w: message is nil", ErrClientKE2Invalid)

	// ErrClientKE2InvalidCredentialResponse indicates that the credential response in the KE2 message is invalid.
	ErrClientKE2InvalidCredentialResponse = prefixError(ErrClientKE2Invalid, ErrInvalidCredentialResponse)

	// ErrClientKE2InvalidEvaluatedMessage indicates that the evaluated message in the KE2 message is invalid.
	ErrClientKE2InvalidEvaluatedMessage = prefixError(ErrClientKE2Invalid, ErrInvalidEvaluatedMessage)

	// ErrClientKE2MissingServerKeyShare indicates that the KE2 message is missing the server's public key share.
	ErrClientKE2MissingServerKeyShare = fmt.Errorf("%w: missing server public key share", ErrClientKE2Invalid)

	// ErrClientKE2InvalidServerKeyShare indicates that the server's public key share in the KE2 message is invalid.
	ErrClientKE2InvalidServerKeyShare = prefixError(ErrClientKE2Invalid, ErrInvalidServerKeyShare)

	// ErrClientKE2InvalidMaskedLength indicates that the length of the masked response in the KE2 message is invalid.
	ErrClientKE2InvalidMaskedLength = prefixError(ErrClientKE2Invalid, ErrInvalidMaskedLength)

	// ErrClientKE2NoMaskingNonce indicates that the KE2 message does not contain a masking nonce, which is required.
	ErrClientKE2NoMaskingNonce = fmt.Errorf("%w: no masking nonce", ErrClientKE2Invalid)

	// ErrInvalidMaskedLength happens when the masked response length in KE2 is invalid.
	ErrInvalidMaskedLength = errors.New("invalid masked response length")

	// ErrClientPreExistingKeyShare indicates that the client state already contains a secret key share, which indicates
	// that a prior run of GenerateKE1 was attempted. The client state must be flushed before starting a new run.
	ErrClientPreExistingKeyShare = errors.New("an AKE secret key share exists in the client state, indicating a" +
		" prior run. Flush the Client state before starting a new run of the protocol")

	// ErrClientExistingKeyShare indicates that the client state already contains a secret key share, but either another
	// key or a seed have been provided as optional arguments to GenerateKE3. It is not recommended to set the key share
	// in the options if the client state already handles it. This error indicates a misunderstanding of the protocol
	// and misuse of the library.
	ErrClientExistingKeyShare = errors.New("an AKE secret key share exists in the client state, but there's also one" +
		" was provided in the options, and only one must be set. It doesn't look like you know what you're doing")
)

// Client options errors.
var (
	// ErrClientInvalidOptions indicates that the client options are invalid.
	ErrClientInvalidOptions = errors.New("invalid client options")

	// ErrClientInvalidOptionsOPRFBlind indicates that the OPRF blind provided in the client options is invalid.
	ErrClientInvalidOptionsOPRFBlind = fmt.Errorf("%w: invalid OPRF blind", ErrClientInvalidOptions)

	// ErrClientInvalidOptionsNoOPRFBlind indicates that neither the client state nor options contain an OPRF blind.
	ErrClientInvalidOptionsNoOPRFBlind = fmt.Errorf("%w: no OPRF blind in state or options. "+
		"Restart the authentication protocol", ErrClientInvalidOptions)

	// ErrClientInvalidOptionsNoKeyShare indicates that the client state and options do not contain an ephemeral secret
	// key share, which indicates no prior run of the GenerateKE1 method.
	ErrClientInvalidOptionsNoKeyShare = fmt.Errorf("%w: no ephemeral secret key share in state or options. "+
		"Restart the authentication protocol", ErrClientInvalidOptions)

	// ErrClientInvalidOptionsKE1Missing indicates that the KE1 message is missing in the client state and options.
	ErrClientInvalidOptionsKE1Missing = fmt.Errorf("%w: no KE1 message in state or options. "+
		"Restart the authentication protocol", ErrClientInvalidOptions)

	// ErrClientInvalidOptionsDoubleKE1 indicates that a KE1 message already exists in the client state, but a KE1 message has
	// also been provided in the options.
	ErrClientInvalidOptionsDoubleKE1 = fmt.Errorf("%w: a KE1 message already exists in the client state, but a "+
		"KE1 message has also been provided in the options", ErrClientInvalidOptions)

	// ErrClientInvalidOptionsInvalidKE1 indicates that the KE1 message provided in the client options is invalid.
	ErrClientInvalidOptionsInvalidKE1 = prefixError(ErrClientInvalidOptions, ErrInvalidKE1)

	// ErrClientInvalidOptionsDoubleOPRFBlind indicates that an OPRF blind already exists in the client state, but a blind has
	// also been provided in the options.
	ErrClientInvalidOptionsDoubleOPRFBlind = fmt.Errorf("%w: an OPRF blind already exists in the client state, "+
		"but a blind has also been provided in the options", ErrClientInvalidOptions)
)

// Miscellaneous errors.
var (
	// ErrInvalidPrivateKey indicates that the provided private key is invalid.
	ErrInvalidPrivateKey = errors.New("invalid private key")

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

	// ErrPrivateKeyZero indicates the provided private key is zero.
	ErrPrivateKeyZero = errors.New("private key is zero")

	// ErrPublicKeyIdentity indicates the provided public key is the identity element (point at infinity).
	ErrPublicKeyIdentity = errors.New("public key is identity element")
)

// Deserializer errors.
var (
	// ErrDecoding indicates a decoding error.
	ErrDecoding = errors.New("decoding error")

	// ErrInvalidPrivateKeyEncoding indicates the provided private key encoding is invalid.
	ErrInvalidPrivateKeyEncoding = errors.New("invalid private key encoding")

	// ErrInvalidPublicKeyEncoding indicates the provided public key encoding is invalid.
	ErrInvalidPublicKeyEncoding = errors.New("invalid public key encoding")

	// ErrInvalidMessageLength indicates the provided message length is invalid for the configuration.
	ErrInvalidMessageLength = errors.New("invalid message length for the configuration")

	// ErrInvalidClientKeyShare indicates the provided ephemeral client public key is invalid.
	ErrInvalidClientKeyShare = errors.New("invalid client key share")

	// ErrInvalidServerKeyShare indicates the provided ephemeral server public key is invalid.
	ErrInvalidServerKeyShare = errors.New("invalid server key share")

	// ErrInvalidServerPK indicates the provided server public key is invalid.
	ErrInvalidServerPK = errors.New("invalid server public key")

	// ErrInvalidClientPublicKey indicates the provided client public key is invalid.
	ErrInvalidClientPublicKey = errors.New("invalid client public key")

	// ErrInvalidEncodingLength indicates that the length of the input is not valid for the configuration.
	ErrInvalidEncodingLength = errors.New("invalid encoding length")
)

// Message errors.
var (
	// ErrInvalidRegistrationRequest indicates an error with a registration request.
	ErrInvalidRegistrationRequest = errors.New("invalid registration request")

	// ErrInvalidRegistrationResponse indicates an error with a registration response.
	ErrInvalidRegistrationResponse = errors.New("invalid registration response")

	// ErrInvalidRegistrationRecord indicates an error with a registration record.
	ErrInvalidRegistrationRecord = errors.New("invalid registration record")

	// ErrInvalidKE1 indicates an error with a KE1 message.
	ErrInvalidKE1 = errors.New("invalid ke1 message")

	// ErrInvalidCredentialResponse indicates an error with a credential response.
	ErrInvalidCredentialResponse = errors.New("invalid credential response")

	// ErrInvalidKE2 indicates an error with a KE2 message.
	ErrInvalidKE2 = errors.New("invalid ke2 message")

	// ErrInvalidKE3 indicates an error with a KE3 message.
	ErrInvalidKE3 = errors.New("invalid ke3 message")

	// ErrRegistrationRequestNil indicates that the registration request is nil.
	ErrRegistrationRequestNil = fmt.Errorf("%w: registration request is nil", ErrInvalidRegistrationRequest)

	// ErrRegistrationRequestInvalidMessage indicates that the blinded message in the registration request is invalid.
	ErrRegistrationRequestInvalidMessage = prefixError(ErrInvalidRegistrationRequest, ErrInvalidBlindedMessage)

	// ErrInvalidBlindedMessage indicates that the blinded message generated by the client is invalid.
	ErrInvalidBlindedMessage = errors.New("invalid blinded message")

	// ErrInvalidEvaluatedMessage indicates that the evaluated message generated by the server is invalid.
	ErrInvalidEvaluatedMessage = errors.New("invalid OPRF evaluated message")
)

func prefixError(prefix, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%w: %w", prefix, err)
}
