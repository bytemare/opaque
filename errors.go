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

// TODO: centralise all errors here
// TODO: verify all errors have been tested against (add a lint or check?)

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

	// ErrNoCredentialIdentifier indicates no credential identifier has been provided.
	ErrNoCredentialIdentifier = errors.New("no credential identifier provided")

	// ErrOPRFKeyNoSeedAndCredID indicates that neither the OPRF seed nor the credential identifier has been provided.
	ErrOPRFKeyNoSeedAndCredID = errors.New("no OPRF seed or credential identifier provided, cannot derive OPRF key")

	// ErrCredentialIdentifierWithSeed indicates that the credential identifier should not be provided if the client
	//  OPRF key is set. This is to avoid confusion in the usage of the secret OPRF seed.
	ErrCredentialIdentifierWithSeed = errors.New("the credential identifier should not be provided with a client" +
		" OPRF seed, to avoid usage confusion")

	// ErrAkeInvalidClientMac indicates that the MAC contained in the KE3 message is not valid in the given session.
	ErrAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

	// ErrInvalidState indicates that the given state is not valid due to a wrong length.
	ErrInvalidState = errors.New("invalid state length")

	errKeyMaterialPrefix = errors.New("invalid server key material")

	// ErrServerKeyMaterialNilPKS indicates that the server's public key is nil.
	ErrServerKeyMaterialNilPKS = fmt.Errorf("%w: server public key is nil", errKeyMaterialPrefix)

	// ErrServerKeyMaterialPKSInvalidLength indicates the input public key is not of right length.
	ErrServerKeyMaterialPKSInvalidLength = fmt.Errorf("%w: server public key length is invalid", errKeyMaterialPrefix)

	// ErrServerKeyMaterialPKSBase indicates that the server's public key is the group base element.
	ErrServerKeyMaterialPKSBase = fmt.Errorf(
		"%w: server public key cannot be the group base element",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialNil indicates that the server's key material has not been set.
	ErrServerKeyMaterialNil = fmt.Errorf(
		"%w: key material not set - use SetKeyMaterial() to set and validate values",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialInvalid indicates that the server's key material is not valid.
	ErrServerKeyMaterialInvalid = fmt.Errorf(
		"%w: use SetKeyMaterial() to set and validate values",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialNoOPRFSeed indicates that no OPRF seed has been provided in the server key material.
	ErrServerKeyMaterialNoOPRFSeed = fmt.Errorf("%w: no OPRF seed provided", errKeyMaterialPrefix)

	// ErrServerKeyMaterialInvalidOPRFSeedLength indicates that the OPRF seed is not of right length.
	ErrServerKeyMaterialInvalidOPRFSeedLength = fmt.Errorf(
		"%w: invalid OPRF seed length (must be of hash output length)",
		errKeyMaterialPrefix,
	)

	// ErrServerKeyMaterialZeroSKS indicates that the server's private key is a zero scalar.
	ErrServerKeyMaterialZeroSKS = fmt.Errorf("%w: server private key is zero", errKeyMaterialPrefix)

	// ErrServerKeyMaterialNilSKS indicates that the server's private key is a nil.
	ErrServerKeyMaterialNilSKS = fmt.Errorf("%w: server private key is nil", errKeyMaterialPrefix)

	// ErrServerKeyMaterialSKSInvalidGroup indicates that the server's secret key does not match the configuration's group.
	ErrServerKeyMaterialSKSInvalidGroup = fmt.Errorf(
		"%w: server secret key does not match the configuration's group",
		errKeyMaterialPrefix,
	)

	errRecordPrefix = errors.New("invalid client record")

	// ErrClientRecordNil indicates that the client record is nil.
	ErrClientRecordNil = fmt.Errorf("%w: client record is nil", errRecordPrefix)

	// ErrClientRecordNilRegistrationRecord indicates that the registration record contained in the client record is nil.
	ErrClientRecordNilRegistrationRecord = fmt.Errorf("%w: registration record is nil", errRecordPrefix)

	// ErrClientRecordNilPubKey indicates that the client's public key is nil.
	ErrClientRecordNilPubKey = fmt.Errorf("%w: client public key is nil", errRecordPrefix)

	// ErrClientRecordPublicKeyGroupMismatch indicates that the client's public key group does not match the
	// configuration's group.
	ErrClientRecordPublicKeyGroupMismatch = fmt.Errorf(
		"%w: client public key group does not match the configuration's group",
		errRecordPrefix,
	)

	// ErrClientRecordInvalidEnvelopeLength indicates the envelope contained in the record is of invalid length.
	ErrClientRecordInvalidEnvelopeLength = fmt.Errorf("%w: invalid envelope length", errRecordPrefix)

	// ErrClientRecordInvalidMaskingKeyLength indicates that the length of the masking key contained in the record
	// is not valid.
	ErrClientRecordInvalidMaskingKeyLength = fmt.Errorf("%w: invalid masking key length", errRecordPrefix)
)

// Client errors.
var (
	// ErrKe1Missing happens when GenerateKE3 is called and the client has no Ke1 in state and nonce if provided as an
	// option.
	ErrKe1Missing = errors.New("client state: missing KE1 message - call GenerateKE1 first")

	// ErrInvalidMaskedLength happens when the masked response length in KE2 is invalid.
	ErrInvalidMaskedLength = errors.New("invalid masked response length")

	// ErrClientAkeFailedHandshakeServerMac indicates a failed handshake because the server's MAC KE2 could not be
	// verified. Execution of the connection must be aborted.
	ErrClientAkeFailedHandshakeServerMac = errors.New("3DH handshake failed: invalid server mac")

	// ErrClientPreExistingKeyShare indicates that the client state already contains a secret key share, which indicates
	// that a prior run of GenerateKE1 was attempted. The client state must be flushed before starting a new run.
	ErrClientPreExistingKeyShare = errors.New("an AKE secret key share exists in the client state, indicating a" +
		" prior run. Flush the Client state before starting a new run of the protocol")

	// ErrClientNoKeyShare indicates that the client state and options do not contain an ephemeral secret key share,
	// which indicates no prior run of the GenerateKE1 method.
	ErrClientNoKeyShare = errors.New("no ephemeral secret key share found in the client state or options. Restart" +
		" the authentication protocol")

	// ErrClientExistingKeyShare indicates that the client state already contains a secret key share, but either another
	// key or a seed have been provided as optional arguments to GenerateKE3. It is not recommended to set the key share
	// in the options if the client state already handles it. This error indicates a misunderstanding of the protocol
	// and misuse of the library.
	ErrClientExistingKeyShare = errors.New("an AKE secret key share exists in the client state, but there's also one" +
		" was provided in the options, and only one must be set. It doesn't look like you know what you're doing")

	// ErrClientDifferentKeyShare indicates that the client state already contains a secret key share, and a different one
	// was provided in the options. It is not recommended to set the key share in the options if the client state already
	// handles it. This error indicates a misunderstanding of the protocol and misuse of the library.
	ErrClientDifferentKeyShare = errors.New("an AKE secret key share exists in the client state, but a different" +
		" one was provided in the options, and only one must be set. It doesn't look like you know what you're doing")

	// ErrServerOptionsMaskingNonceLength indicates that the MaskingNonce provided in the ServerOptions does not have
	// the required length for the configuration. Note that providing a nonce is not required, as a new nonce will be generated
	// internally at each call.
	ErrServerOptionsMaskingNonceLength = errors.New("the provided masking key does not have the required structure" +
		" (it's all zeroes or wrong length) for the configuration")

	// ErrServerOptionsClientOPRFKey indicates the provided OPRF key for the client is invalid. Note that providing this
	// key is not required. Use this option at your own risk. The
	ErrServerOptionsClientOPRFKey = errors.New("the provided OPRF key for the client is invalid: ")
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

	// Misc.

	// ErrPrivateKeyZero indicates the provided private key is zero.
	ErrPrivateKeyZero = errors.New("private key is zero")

	// ErrPublicKeyIdentity indicates the provided public key is the identity element (point at infinity).
	ErrPublicKeyIdentity = errors.New("public key is identity element")
)

// Deserializer errors.
var (
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
)
