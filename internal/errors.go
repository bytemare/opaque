// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"errors"
	"fmt"
)

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

// Server authentication errors: upon error, the protocol must be aborted and the keys must not be used.
var (
	// ErrServerAuthentication indicates that the client failed to authenticate the server.
	ErrServerAuthentication = errors.New("failed to authenticate server")

	// ErrAuthenticationInvalidServerPublicKey indicates the authentication process failed because the server's public
	// key in the KE2 message is invalid.
	ErrAuthenticationInvalidServerPublicKey = errors.New("decrypted server public key is invalid")

	// ErrInvalidServerMac indicates that the MAC contained in the KE2 message is not valid in the given session.
	ErrInvalidServerMac = errors.New("invalid server mac")

	// ErrEnvelopeInvalidMac indicates that the authentication tag in the envelope is invalid.
	ErrEnvelopeInvalidMac = errors.New("invalid envelope authentication tag")
)

// Client authentication errors: upon error, the protocol must be aborted and the keys must not be used.
var (
	// ErrClientAuthentication indicates that the server failed to authenticate the client.
	ErrClientAuthentication = errors.New("failed to authenticate client")

	// ErrInvalidClientMac indicates that the MAC contained in the KE3 message is not valid in the given session.
	// Execution of the connection must be aborted.
	ErrInvalidClientMac = errors.New("invalid client mac")
)

// ServerKeyMaterial errors.
var (
	// ErrInvalidGroupEncoding indicates that the group encoding in the server's key material is not
	// valid or the group is not available.
	ErrInvalidGroupEncoding = errors.New("invalid group encoding")

	// ErrDecodingEmptyHex indicates that the provided hex string is empty.
	ErrDecodingEmptyHex = errors.New("empty hex string")

	// ErrServerKeyMaterialNil indicates that the server's key material has not been set.
	ErrServerKeyMaterialNil = errors.New("key material not set - use SetKeyMaterial() to set and validate values")

	// ErrInvalidOPRFSeedLength indicates that the OPRF seed is not of right length.
	ErrInvalidOPRFSeedLength = errors.New("invalid OPRF seed length (must be equal to the hash output length)")

	// ErrOPRFKeyNoSeed happens when no OPRF key seed is provided.
	ErrOPRFKeyNoSeed = errors.New("no OPRF key seed provided")
)

// Server options errors.
var (
	// ErrServerInvalidPublicKeyLength indicates that the length of the server public key is not
	// valid for the configuration.
	ErrServerInvalidPublicKeyLength = errors.New("the provided server public key is not a valid encoding for the " +
		"configuration")

	// ErrClientOPRFKey indicates the provided OPRF key for the client is invalid. Note that providing this
	// key is not required. Use this option at your own risk.
	ErrClientOPRFKey = errors.New("the provided OPRF key for the client is invalid")

	// ErrMaskingNonceLength indicates that the MaskingNonce provided in the ServerOptions does not have
	// the required length for the configuration. Note that providing a nonce is not required, as a new nonce will be
	// generated internally at each call.
	ErrMaskingNonceLength = errors.New(
		"the provided masking nonce does not have the required length for the configuration",
	)
)

// ClientRecord errors.
var (
	// ErrClientRecordNil indicates that the client record is nil.
	ErrClientRecordNil = errors.New("client record is nil")

	// ErrNilRegistrationRecord indicates that the registration record contained in the client record is nil.
	ErrNilRegistrationRecord = errors.New("registration record is nil")

	// ErrNoCredentialIdentifier indicates no credential identifier has been provided.
	ErrNoCredentialIdentifier = errors.New("no credential identifier provided")

	// ErrEnvelopeInvalid indicates that the envelope or its components are invalid.
	ErrEnvelopeInvalid = errors.New("envelope error")

	// ErrInvalidMaskingKey indicates that the length of the masking key is not valid.
	ErrInvalidMaskingKey = errors.New("invalid masking key")
)

// Client state errors.
var (
	// ErrClientPreviousBlind indicates that the client state already contains an OPRF blind, which indicates a prior run
	// of the protocol.
	ErrClientPreviousBlind = errors.New("an OPRF blind already exists in the client state, indicating a prior run" +
		"of the protocol. Use a new client instance or clear the state with ClearState() before starting a new run")

	// ErrClientPreExistingKeyShare indicates that the client state already contains a secret key share, which indicates
	// that a prior run of GenerateKE1 was attempted. The client state must be flushed before starting a new run.
	ErrClientPreExistingKeyShare = errors.New("an AKE secret key share exists in the client state, indicating a" +
		" prior run. Flush the Client state before starting a new run of the protocol")
)

// KE2 related errors.
var (
	// ErrKE2Nil indicates that the KE2 message is nil.
	ErrKE2Nil = errors.New("KE2 is nil")

	// ErrCredentialResponseNil indicates that the credential response is nil.
	ErrCredentialResponseNil = errors.New("credential response is nil")

	// ErrCredentialResponseInvalid indicates that the credential response is invalid.
	ErrCredentialResponseInvalid = errors.New("credential response is invalid")

	// ErrCredentialResponseNoMaskingNonce indicates that the KE2 message does not contain a masking nonce,
	// which is required.
	ErrCredentialResponseNoMaskingNonce = errors.New("no masking nonce")

	// ErrCredentialResponseInvalidMaskingNonce indicates that the masking nonce in the credential response is invalid.
	ErrCredentialResponseInvalidMaskingNonce = errors.New("invalid masking nonce")

	// ErrCredentialResponseInvalidMaskedResponse indicates that the masked response is invalid.
	ErrCredentialResponseInvalidMaskedResponse = errors.New("invalid masked response")

	ErrMissingMAC = errors.New("missing MAC")

	// ErrServerKeyShareMissing indicates that the KE2 message is missing the server's public key share.
	ErrServerKeyShareMissing = errors.New("no server public key share")

	// ErrInvalidServerKeyShare indicates the provided ephemeral server public key is invalid.
	ErrInvalidServerKeyShare = errors.New("invalid server key share")
)

// Client options errors.
var (
	// ErrNoOPRFBlind indicates that neither the client state nor options contain an OPRF blind.
	ErrNoOPRFBlind = errors.New("no OPRF blind in state or options. " +
		"Restart the authentication protocol")

	// ErrInvalidOPRFBlind indicates that the provided OPRF blind is invalid.
	ErrInvalidOPRFBlind = errors.New("invalid OPRF blind")

	// ErrDoubleOPRFBlind indicates that an OPRF blind already exists in the client state, but a blind has
	// also been provided in the options.
	ErrDoubleOPRFBlind = errors.New("an OPRF blind already exists in the client state, " +
		"but a blind has also been provided in the options")

	// ErrEnvelopeNonceOptions indicates that the provided nonce in the options is invalid.
	ErrEnvelopeNonceOptions = errors.New("failed to validate envelope nonce parameters")

	// ErrClientNoKeyShare indicates that the client state and options do not contain an ephemeral secret
	// key share, which indicates no prior run of the GenerateKE1 method.
	ErrClientNoKeyShare = errors.New("no ephemeral secret key share in state or options. " +
		"Restart the authentication protocol")

	// ErrClientExistingKeyShare indicates that the client state already contains a secret key share, but either another
	// key or a seed have been provided as optional arguments to GenerateKE3. It is not recommended to set the key share
	// in the options if the client state already handles it. This error indicates a misunderstanding of the protocol
	// and misuse of the library.
	ErrClientExistingKeyShare = errors.New("an AKE secret key share exists in the client state, but there's also one" +
		" provided in the options, but only one must be set. It doesn't look like you know what you're doing")

	// ErrKE1Missing indicates that the KE1 message is missing in the client state and options.
	ErrKE1Missing = errors.New("no KE1 message in state or options. " +
		"Restart the authentication protocol")

	// ErrDoubleKE1 indicates that a KE1 message already exists in the client state, but a KE1 message has
	// also been provided in the options.
	ErrDoubleKE1 = errors.New("a KE1 message already exists in the client state, but a " +
		"KE1 message has also been provided in the options. It's recommended to prefer using the state to avoid confusion")
)

// Miscellaneous errors.
var (
	// ErrInvalidPrivateKey indicates that the provided private key is invalid.
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidPublicKey indicates that the provided public key is invalid.
	ErrInvalidPublicKey = errors.New("invalid public key")

	// ErrInvalidPublicKeyBytes indicates that the provided public key bytes are not valid.
	ErrInvalidPublicKeyBytes = errors.New("invalid public key encoding")

	// ErrInvalidScalar indicates that the provided scalar is invalid.
	ErrInvalidScalar = errors.New("invalid scalar")

	// ErrScalarNil indicates the provided scalar is nil.
	ErrScalarNil = errors.New("scalar is nil")

	// ErrScalarGroupMismatch indicates the provided scalar does not match the group.
	ErrScalarGroupMismatch = fmt.Errorf("scalar: %w", ErrWrongGroup)

	// ErrScalarZero indicates the provided scalar is zero.
	ErrScalarZero = errors.New("scalar is zero")

	// ErrInvalidElement indicates that the provided element is invalid.
	ErrInvalidElement = errors.New("invalid element")

	// ErrElementNil indicates the provided element is nil.
	ErrElementNil = errors.New("element is nil")

	// ErrElementIdentity indicates the provided element is the identity element (point at infinity).
	ErrElementIdentity = errors.New("element is the identity element")

	// ErrElementIsBase indicates the provided element is the base point (generator).
	ErrElementIsBase = errors.New("element is the base point (generator)")

	// ErrPrivateKeyZero indicates the provided private key is zero.
	ErrPrivateKeyZero = errors.New("private key is zero")

	// ErrSecretShareInvalid indicates the provided secret share is invalid.
	ErrSecretShareInvalid = errors.New("invalid secret share")

	// ErrWrongGroup indicates that the provided group does not match the expected group.
	ErrWrongGroup = errors.New("does not match the group")

	// ErrElementGroupMismatch indicates the provided element does not match the group.
	ErrElementGroupMismatch = fmt.Errorf("element: %w", ErrWrongGroup)

	// ErrInvalidClientPublicKey indicates the provided client public key is invalid.
	ErrInvalidClientPublicKey = errors.New("invalid client public key")

	// ErrSliceIsAllZeros indicates that the provided slice is all zeros.
	ErrSliceIsAllZeros = errors.New("slice is all zeros")
)

// KE1 related errors.
var (
	// ErrKE1Nil indicates that the KE1 message is nil.
	ErrKE1Nil = errors.New("KE1 is nil")

	// ErrInvalidClientKeyShare indicates the provided ephemeral client public key is invalid.
	ErrInvalidClientKeyShare = errors.New("invalid client key share")
)

// RegistrationResponse related errors.
var (
	// ErrInvalidServerPublicKey indicates the provided server public key is invalid.
	ErrInvalidServerPublicKey = errors.New("invalid server public key")
)

// Deserializer errors.
var (
	// ErrInvalidContextEncoding indicates that the provided context encoding in the configuration is invalid.
	ErrInvalidContextEncoding = errors.New("invalid context encoding")

	// ErrInvalidMessageLength indicates the provided message length is invalid for the configuration.
	ErrInvalidMessageLength = errors.New("invalid message length for the configuration")

	// ErrInvalidEncodingLength indicates that the length of the input is not valid for the configuration.
	ErrInvalidEncodingLength = errors.New("invalid encoding length")
)

// Message errors.
var (
	// ErrRegistrationRequestNil indicates that the registration request is nil.
	ErrRegistrationRequestNil = errors.New("registration request is nil")

	// ErrRegistrationResponseNil indicates that the registration response is nil.
	ErrRegistrationResponseNil = errors.New("registration response is nil")

	// ErrRegistrationResponseEmpty indicates that the registration response has empty fields.
	ErrRegistrationResponseEmpty = errors.New("registration response has empty fields")

	// ErrInvalidBlindedMessage indicates that the blinded message generated by the client is invalid.
	ErrInvalidBlindedMessage = errors.New("invalid blinded message")

	// ErrInvalidEvaluatedMessage indicates that the evaluated message generated by the server is invalid.
	ErrInvalidEvaluatedMessage = errors.New("invalid OPRF evaluated message")

	// ErrKE3Nil indicates that the KE3 message is nil.
	ErrKE3Nil = errors.New("KE3 is nil")

	// ErrMissingNonce indicates that the nonce is missing.
	ErrMissingNonce = errors.New("missing nonce")
)
