// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"crypto"
	"encoding/hex"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"

	ksf2 "github.com/bytemare/opaque/internal/ksf"
)

// TestNewClient_DefaultConfiguration guarantees that passing nil configuration falls back to the hardened defaults, which is essential so applications relying on the safe baseline do not accidentally run with zeroed parameters.
func TestNewClient_DefaultConfiguration(t *testing.T) {
	client, err := opaque.NewClient(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Generating KE1 should reflect the default configuration's AKE ecc.
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}

	if ke1.ClientKeyShare.Group() != opaque.DefaultConfiguration().AKE.Group() {
		t.Fatalf(
			"expected client keyshare group %v, got %v",
			opaque.DefaultConfiguration().AKE.Group(),
			ke1.ClientKeyShare.Group(),
		)
	}
}

// TestClient_RegistrationInit_PreviousBlind ensures the client rejects attempts to start a second registration while a previous OPRF blind is still cached, preventing state reuse that could leak correlation information.
func TestClient_RegistrationInit_PreviousBlind(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client := getClient(t2, conf)

		if _, err := client.RegistrationInit(password); err != nil {
			t2.Fatal(err)
		}

		expectErrors(t2, func() error {
			_, err := client.RegistrationInit(password)
			return err
		}, opaque.ErrClientState, internal.ErrClientPreviousBlind)
	})
}

// TestClient_RegistrationInit_InvalidOptions_OPRFBlind checks that supplying an OPRF blind from the wrong group is caught, preserving group separation guarantees required by the protocol.
func TestClient_RegistrationInit_InvalidOptions_OPRFBlind(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client := getClient(t2, conf)

		// Build an OPRF blind from a different group than the configuration requires.
		var otherGroup ecc.Group
		if conf.internal.Group == ecc.Ristretto255Sha512 {
			otherGroup = ecc.P256Sha256
		} else {
			otherGroup = ecc.Ristretto255Sha512
		}
		badBlind := otherGroup.NewScalar().Random()

		expectErrors(t2, func() error {
			_, err := client.RegistrationInit(password, &opaque.ClientOptions{OPRFBlind: badBlind})
			return err
		}, opaque.ErrClientOptions, internal.ErrInvalidOPRFBlind)
	})
}

// TestClient_RegistrationFinalize_InvalidServerKeyLength verifies that truncated server public keys are rejected before envelope processing, protecting the registration flow from malformed key material.
func TestClient_RegistrationFinalize_InvalidServerKeyLength(t *testing.T) {
	testAll(t, func(t *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		req, err := client.RegistrationInit(password)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := server.RegistrationResponse(req, credentialIdentifier, nil)
		if err != nil {
			t.Fatal(err)
		}

		resp.ServerPublicKey = resp.ServerPublicKey[:len(resp.ServerPublicKey)-1]

		expectErrors(t, func() error {
			_, _, err := client.RegistrationFinalize(resp, nil, nil)
			return err
		}, opaque.ErrRegistration, internal.ErrInvalidServerPublicKey, internal.ErrInvalidEncodingLength)
	})
}

// TestClient_RegistrationFinalize_InvalidOptionsAndResponses exercises the full matrix of bad inputs and option combinations so the registration finalization code cannot proceed with inconsistent or attacker-chosen state.
func TestClient_RegistrationFinalize_InvalidOptionsAndResponses(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)

		// Prepare a valid RegistrationRequest/Response to reach options/response validation.
		r1, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}

		// a) Double OPRF blind: state already has one. Providing another must error.
		expectErrors(t2, func() error {
			_, _, err := client.RegistrationFinalize(
				r2,
				nil,
				nil,
				&opaque.ClientOptions{OPRFBlind: conf.internal.Group.NewScalar().Random()},
			)
			return err
		}, opaque.ErrClientOptions, internal.ErrDoubleOPRFBlind)

		// b) Invalid RegistrationResponse: nil
		expectErrors(t2, func() error {
			_, _, err := client.RegistrationFinalize(nil, nil, nil)
			return err
		}, opaque.ErrRegistration, internal.ErrRegistrationResponseNil)

		// c) Invalid RegistrationResponse: empty fields
		emptyResp := &message.RegistrationResponse{}
		expectErrors(t2, func() error {
			_, _, err := client.RegistrationFinalize(emptyResp, nil, nil)
			return err
		}, opaque.ErrRegistration, internal.ErrRegistrationResponseEmpty)

		// d) No prior blind and no OPRFBlind option
		client2 := getClient(t2, conf)
		expectErrors(t2, func() error {
			_, _, err := client2.RegistrationFinalize(r2, nil, nil)
			return err
		}, opaque.ErrClientOptions, internal.ErrNoOPRFBlind)

		// e) Options provided without blind
		client3 := getClient(t2, conf)
		expectErrors(t2, func() error {
			_, _, err := client3.RegistrationFinalize(nil, nil, nil, &opaque.ClientOptions{})
			return err
		}, opaque.ErrClientOptions, internal.ErrNoOPRFBlind)

		// f) KSF options: wrong parameter count
		// Use a valid blind from state to pass blind checks.
		client4 := getClient(t2, conf)
		r1b, err := client4.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2b, err := server.RegistrationResponse(r1b, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}
		badParams := []int{1} // wrong count for Argon2id default (expects 3)
		expectErrors(t2, func() error {
			_, _, err := client4.RegistrationFinalize(r2b, nil, nil, &opaque.ClientOptions{KSFParameters: badParams})
			return err
		}, opaque.ErrClientOptions, ksf2.ErrParameters)

		// g) KSF options: negative length
		client5 := getClient(t2, conf)
		r1c, err := client5.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2c, err := server.RegistrationResponse(r1c, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}
		expectErrors(t2, func() error {
			_, _, err := client5.RegistrationFinalize(r2c, nil, nil, &opaque.ClientOptions{KSFLength: -1})
			return err
		}, opaque.ErrClientOptions, ksf2.ErrNegativeKSFLength)

		// h) Envelope nonce options: length mismatch
		client6 := getClient(t2, conf)
		r1d, err := client6.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2d, err := server.RegistrationResponse(r1d, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}
		nonce := internal.RandomBytes(conf.internal.NonceLen)
		expectErrors(t2, func() error {
			_, _, err := client6.RegistrationFinalize(
				r2d,
				nil,
				nil,
				&opaque.ClientOptions{EnvelopeNonce: nonce, EnvelopeNonceLength: conf.internal.NonceLen - 1},
			)
			return err
		}, opaque.ErrClientOptions, internal.ErrEnvelopeNonceOptions, internal.ErrSliceDifferentLength)

		// i) Envelope nonce options: shorter than reference with no override
		client7 := getClient(t2, conf)
		r1e, err := client7.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2e, err := server.RegistrationResponse(r1e, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}
		shortNonce := internal.RandomBytes(conf.internal.NonceLen - 1)
		expectErrors(t2, func() error {
			_, _, err := client7.RegistrationFinalize(r2e, nil, nil, &opaque.ClientOptions{EnvelopeNonce: shortNonce})
			return err
		}, opaque.ErrClientOptions, internal.ErrEnvelopeNonceOptions, internal.ErrSliceShorterLength)

		// j) Envelope nonce options: negative length
		client8 := getClient(t2, conf)
		r1f, err := client8.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2f, err := server.RegistrationResponse(r1f, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}
		// Provide a non-nil nonce so negative length is validated (input!=nil)
		someNonce := internal.RandomBytes(conf.internal.NonceLen)
		expectErrors(t2, func() error {
			_, _, err := client8.RegistrationFinalize(
				r2f,
				nil,
				nil,
				&opaque.ClientOptions{EnvelopeNonce: someNonce, EnvelopeNonceLength: -1},
			)
			return err
		}, opaque.ErrClientOptions, internal.ErrEnvelopeNonceOptions, internal.ErrProvidedLengthNegative)
	})
}

// TestClient_RegistrationFinalize_InvalidEvaluatedMessage proves that an evaluated OPRF element from a foreign group is rejected, maintaining the curve membership guarantees required for OPAQUE security proofs.
func TestClient_RegistrationFinalize_InvalidEvaluatedMessage(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)

		req, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}

		resp, err := server.RegistrationResponse(req, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}

		resp.EvaluatedMessage = getOtherGroup(conf).Base().Multiply(getOtherGroup(conf).NewScalar().Random())

		expectErrors(t2, func() error {
			_, _, err := client.RegistrationFinalize(resp, nil, nil)
			return err
		}, opaque.ErrRegistration, internal.ErrInvalidEvaluatedMessage)
	})
}

// TestClient_RegistrationFinalize_KSFCustomization demonstrates that callers can tune KSF parameters without breaking record derivation, which is important for deployments that increase work factors over time.
func TestClient_RegistrationFinalize_KSFCustomization(t *testing.T) {
	testAll(t, func(t *testing.T, conf *configuration) {
		params := conf.internal.KSF.Parameters()
		if len(params) == 0 {
			t.Skip("KSF has no tunable parameters")
		}

		client, server := setup(t, conf)
		req, err := client.RegistrationInit(password)
		if err != nil {
			t.Fatal(err)
		}

		resp, err := server.RegistrationResponse(req, credentialIdentifier, nil)
		if err != nil {
			t.Fatal(err)
		}

		custom := append([]int(nil), params...)
		options := &opaque.ClientOptions{
			KSFParameters: custom,
			KSFLength:     conf.internal.KDF.Size(),
		}

		record, _, err := client.RegistrationFinalize(resp, nil, nil, options)
		if err != nil {
			t.Fatalf("unexpected error with custom KSF options: %v", err)
		}
		if record == nil {
			t.Fatal("expected non-nil registration record")
		}
	})
}

// TestClient_GenerateKE1_PreviousBlind confirms the client will not reuse a cached blind, protecting unlinkability across authentication attempts.
func TestClient_GenerateKE1_PreviousBlind(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client := getClient(t2, conf)
		if _, err := client.GenerateKE1(password); err != nil {
			t2.Fatal(err)
		}

		expectErrors(t2, func() error {
			_, err := client.GenerateKE1(password)
			return err
		}, opaque.ErrClientState, internal.ErrClientPreviousBlind)
	})
}

// TestClient_GenerateKE1_InvalidOptions validates that the client catches malformed blinding and bad secret-key-share inputs, preventing attackers from pushing the state machine onto an unsafe curve.
func TestClient_GenerateKE1_InvalidOptions(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		// Bad OPRF blind ecc.
		client := getClient(t2, conf)
		var otherGroup ecc.Group
		if conf.internal.Group == ecc.Ristretto255Sha512 {
			otherGroup = ecc.P256Sha256
		} else {
			otherGroup = ecc.Ristretto255Sha512
		}
		badBlind := otherGroup.NewScalar().Random()
		testForErrors(t2, &testError{
			name: "bad-oprf-blind",
			f: func() error {
				_, err := client.GenerateKE1(password, &opaque.ClientOptions{OPRFBlind: badBlind})
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrInvalidOPRFBlind},
		})

		// Bad AKE secret share ecc.
		client = getClient(t2, conf)
		badSK := otherGroup.NewScalar().Random()
		testForErrors(t2, &testError{
			name: "bad-ake-secret-share",
			f: func() error {
				_, err := client.GenerateKE1(
					password,
					&opaque.ClientOptions{AKE: &opaque.AKEOptions{SecretKeyShare: badSK}},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrSecretShareInvalid},
		})
	})
}

// TestClient_GenerateKE3_InvalidMaskingNonce ensures malformed masking nonces and responses are caught, which blocks attackers from tampering with the envelope while keeping MACs intact.
func TestClient_GenerateKE3_InvalidMaskingNonce(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		baseline := func() (*opaque.Client, *message.KE2, *opaque.ClientRecord) {
			client, server := setup(t2, conf)
			rec := registration(t2, client, server, password, credentialIdentifier, nil, nil)
			client.ClearState()
			ke1, err := client.GenerateKE1(password)
			if err != nil {
				t2.Fatal(err)
			}
			ke2, _, err := server.GenerateKE2(ke1, rec)
			if err != nil {
				t2.Fatal(err)
			}
			return client, ke2, rec
		}

		// Missing masking nonce
		clientA, ke2A, _ := baseline()
		bad := *ke2A
		bad.CredentialResponse = &message.CredentialResponse{
			EvaluatedMessage: ke2A.CredentialResponse.EvaluatedMessage,
			MaskingNonce:     nil,
			MaskedResponse:   ke2A.CredentialResponse.MaskedResponse,
		}
		expectErrors(t2, func() error {
			_, _, _, err := clientA.GenerateKE3(&bad, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseNoMaskingNonce)

		// Zero masking nonce
		clientB, ke2B, _ := baseline()
		zeros := make([]byte, len(ke2B.CredentialResponse.MaskingNonce))
		bad2 := *ke2B
		bad2.CredentialResponse = &message.CredentialResponse{
			EvaluatedMessage: ke2B.CredentialResponse.EvaluatedMessage,
			MaskingNonce:     zeros,
			MaskedResponse:   ke2B.CredentialResponse.MaskedResponse,
		}
		expectErrors(t2, func() error {
			_, _, _, err := clientB.GenerateKE3(&bad2, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseInvalidMaskingNonce, internal.ErrSliceIsAllZeros)

		// Masked response wrong length
		clientC, ke2C, _ := baseline()
		bad3 := *ke2C
		bad3.CredentialResponse = &message.CredentialResponse{
			EvaluatedMessage: ke2C.CredentialResponse.EvaluatedMessage,
			MaskingNonce:     ke2C.CredentialResponse.MaskingNonce,
			MaskedResponse:   internal.RandomBytes(conf.internal.Group.ElementLength()),
		}
		expectErrors(t2, func() error {
			_, _, _, err := clientC.GenerateKE3(&bad3, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseInvalidMaskedResponse, internal.ErrInvalidEncodingLength)
	})
}

// TestClient_GenerateKE3_InvalidKE2Fields walks through the KE2 validation ladder so any malformed response from the server fails fast before secrets are derived.
func TestClient_GenerateKE3_InvalidKE2Fields(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		// a) nil KE2
		freshClient := getClient(t2, conf)
		testForErrors(t2, &testError{
			name:   "nil-ke2",
			f:      func() error { _, _, _, err := freshClient.GenerateKE3(nil, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrKE2Nil},
		})

		// Build a valid baseline KE2 to mutate.
		client, server := setup(t2, conf)
		rec := registration(t2, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()
		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2, _, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t2.Fatal(err)
		}

		// b) nil credential response
		ke2b := *ke2
		ke2b.CredentialResponse = nil
		testForErrors(t2, &testError{
			name:   "nil-credential-response",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2b, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrCredentialResponseNil},
		})

		// b.1) invalid evaluated message (nil)
		ke2b1 := *ke2
		ke2b1.CredentialResponse = &message.CredentialResponse{
			EvaluatedMessage: nil,
			MaskingNonce:     ke2.CredentialResponse.MaskingNonce,
			MaskedResponse:   ke2.CredentialResponse.MaskedResponse,
		}
		testForErrors(t2, &testError{
			name: "nil-evaluated-message",
			f:    func() error { _, _, _, err := client.GenerateKE3(&ke2b1, nil, nil); return err },
			errors: []error{
				opaque.ErrKE2,
				internal.ErrCredentialResponseInvalid,
				internal.ErrInvalidEvaluatedMessage,
				internal.ErrElementNil,
			},
		})

		// b.2) invalid evaluated message (wrong group)
		ke2b2 := *ke2
		og := getOtherGroup(conf)
		wrongEval := og.Base().Multiply(og.NewScalar().Random())
		ke2b2.CredentialResponse = &message.CredentialResponse{
			EvaluatedMessage: wrongEval,
			MaskingNonce:     ke2.CredentialResponse.MaskingNonce,
			MaskedResponse:   ke2.CredentialResponse.MaskedResponse,
		}
		testForErrors(t2, &testError{
			name: "wrong-group-evaluated-message",
			f:    func() error { _, _, _, err := client.GenerateKE3(&ke2b2, nil, nil); return err },
			errors: []error{
				opaque.ErrKE2,
				internal.ErrCredentialResponseInvalid,
				internal.ErrInvalidEvaluatedMessage,
				internal.ErrElementGroupMismatch,
			},
		})

		// c) missing server key share
		ke2c := *ke2
		ke2c.ServerKeyShare = nil
		testForErrors(t2, &testError{
			name:   "missing-server-keyshare",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2c, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrServerKeyShareMissing},
		})

		// c.1) invalid server key share (wrong group)
		ke2c1 := *ke2
		ke2c1.ServerKeyShare = getOtherGroup(conf).Base().Multiply(getOtherGroup(conf).NewScalar().Random())
		testForErrors(t2, &testError{
			name:   "invalid-server-keyshare",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2c1, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrInvalidServerKeyShare, internal.ErrElementGroupMismatch},
		})

		// d) missing server nonce
		ke2d := *ke2
		ke2d.ServerNonce = nil
		testForErrors(t2, &testError{
			name:   "missing-server-nonce",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2d, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrMissingNonce},
		})

		// e) zero server nonce
		ke2e := *ke2
		ke2e.ServerNonce = make([]byte, conf.internal.NonceLen)
		testForErrors(t2, &testError{
			name:   "zero-server-nonce",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2e, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrMissingNonce, internal.ErrSliceIsAllZeros},
		})

		// f) missing server mac
		ke2f := *ke2
		ke2f.ServerMac = nil
		testForErrors(t2, &testError{
			name:   "missing-server-mac",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2f, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrMissingMAC},
		})

		// g) zero server mac
		ke2g := *ke2
		ke2g.ServerMac = make([]byte, conf.internal.MAC.Size())
		testForErrors(t2, &testError{
			name:   "zero-server-mac",
			f:      func() error { _, _, _, err := client.GenerateKE3(&ke2g, nil, nil); return err },
			errors: []error{opaque.ErrKE2, internal.ErrMissingMAC, internal.ErrSliceIsAllZeros},
		})
	})
}

// TestClient_GenerateKE3_InvalidOptions stresses every invalid client option combination so the KE3 generator stays robust against misconfiguration or malicious overrides.
func TestClient_GenerateKE3_InvalidOptions(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		// Build a valid KE2 as a baseline.
		clientA, server := setup(t2, conf)
		rec := registration(t2, clientA, server, password, credentialIdentifier, nil, nil)
		clientA.ClearState()
		ke1, err := clientA.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2, _, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t2.Fatal(err)
		}

		// a) No options and no prior client state => missing OPRF blind.
		clientB := getClient(t2, conf)
		testForErrors(t2, &testError{
			name:   "no-oprf-blind",
			f:      func() error { _, _, _, err := clientB.GenerateKE3(ke2, nil, nil); return err },
			errors: []error{opaque.ErrClientOptions, internal.ErrNoOPRFBlind},
		})

		// Prepare state for the next invalid options cases.
		clientC := getClient(t2, conf)
		ke1c, err := clientC.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2c, _, err := server.GenerateKE2(ke1c, rec)
		if err != nil {
			t2.Fatal(err)
		}

		// b) Double OPRF blind: state already has one, options also provide one.
		testForErrors(t2, &testError{
			name: "double-oprf-blind",
			f: func() error {
				_, _, _, err := clientC.GenerateKE3(
					ke2c,
					nil,
					nil,
					&opaque.ClientOptions{OPRFBlind: conf.internal.Group.NewScalar().Random()},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrDoubleOPRFBlind},
		})

		// c) Double KE1: KE1 present in state and also provided in options.
		testForErrors(t2, &testError{
			name: "double-ke1",
			f: func() error {
				_, _, _, err := clientC.GenerateKE3(ke2c, nil, nil, &opaque.ClientOptions{KE1: ke1c.Serialize()})
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrDoubleKE1},
		})

		// d) Existing key share in state and also provided in options.
		testForErrors(t2, &testError{
			name: "existing-keyshare-plus-option",
			f: func() error {
				_, _, _, err := clientC.GenerateKE3(
					ke2c,
					nil,
					nil,
					&opaque.ClientOptions{
						AKE: &opaque.AKEOptions{SecretKeyShare: conf.internal.Group.NewScalar().Random()},
					},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrClientExistingKeyShare},
		})

		// e) Missing KE1 in state and options (but with provided OPRF blind).
		clientD := getClient(t2, conf)
		testForErrors(t2, &testError{
			name: "missing-ke1-with-oprf-blind",
			f: func() error {
				_, _, _, err := clientD.GenerateKE3(
					ke2,
					nil,
					nil,
					&opaque.ClientOptions{OPRFBlind: conf.internal.Group.NewScalar().Random()},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrKE1Missing},
		})

		// f) Invalid OPRF blind group in options
		var other ecc.Group
		if conf.internal.Group == ecc.Ristretto255Sha512 {
			other = ecc.P256Sha256
		} else {
			other = ecc.Ristretto255Sha512
		}
		badBlind := other.NewScalar().Random()
		clientE := getClient(t2, conf)
		// Provide a valid KE1 in options but wrong-group blind
		testForErrors(t2, &testError{
			name: "invalid-oprfblind-group",
			f: func() error {
				_, _, _, err := clientE.GenerateKE3(
					ke2,
					nil,
					nil,
					&opaque.ClientOptions{OPRFBlind: badBlind, KE1: ke1.Serialize()},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrInvalidOPRFBlind},
		})

		// g) Invalid KE1 bytes in options
		clientF := getClient(t2, conf)
		badKE1 := internal.RandomBytes(conf.internal.Group.ElementLength()) // wrong total length for KE1
		testForErrors(t2, &testError{
			name: "invalid-ke1-bytes",
			f: func() error {
				_, _, _, err := clientF.GenerateKE3(
					ke2,
					nil,
					nil,
					&opaque.ClientOptions{OPRFBlind: conf.internal.Group.NewScalar().Random(), KE1: badKE1},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrInvalidMessageLength},
		})

		// h) Missing key share when KE1 provided in options
		clientG := getClient(t2, conf)
		testForErrors(t2, &testError{
			name: "missing-keyshare-with-ke1",
			f: func() error {
				_, _, _, err := clientG.GenerateKE3(
					ke2,
					nil,
					nil,
					&opaque.ClientOptions{OPRFBlind: conf.internal.Group.NewScalar().Random(), KE1: ke1.Serialize()},
				)
				return err
			},
			errors: []error{opaque.ErrClientOptions, internal.ErrClientNoKeyShare},
		})
	})
}

// getOtherGroup returns a different group than the current configuration's.
func getOtherGroup(conf *configuration) ecc.Group {
	if conf.internal.Group == ecc.Ristretto255Sha512 {
		return ecc.P256Sha256
	}
	return ecc.Ristretto255Sha512
}

// TestClient_GenerateKE3_BadMaskedResponse verifies the client aborts when the masked envelope response length is inconsistent, preventing accidental truncation or padding oracle issues.
func TestClient_GenerateKE3_BadMaskedResponse(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		sks, pks := conf.conf.KeyGen()
		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sks,
			PublicKeyBytes: pks.Encode(),
			OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatal(err)
		}

		rec, err := buildRecord(t, conf, credentialIdentifier, password)
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		goodLength := conf.internal.Group.ElementLength() + conf.internal.EnvelopeSize

		// too short
		ke2.MaskedResponse = internal.RandomBytes(goodLength - 1)
		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseInvalidMaskedResponse, internal.ErrInvalidEncodingLength)

		// too long
		ke2.MaskedResponse = internal.RandomBytes(goodLength + 1)
		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrKE2, internal.ErrCredentialResponseInvalidMaskedResponse, internal.ErrInvalidEncodingLength)
	})
}

// TestClient_GenerateKE3_InvalidEnvelopeTag shows that tampering with the envelope authentication tag results in an authentication failure, reinforcing the MAC’s role in key confirmation.
func TestClient_GenerateKE3_InvalidEnvelopeTag(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		rec := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		blind := conf.conf.OPRF.Group().NewScalar().Random()

		ke1, err := client.GenerateKE1(password, &opaque.ClientOptions{OPRFBlind: blind})
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t.Fatal(err)
		}

		env, _, err := getEnvelope(conf.internal, blind, password, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = internal.RandomBytes(conf.internal.MAC.Size())
		clearText := encoding.Concat(server.ServerKeyMaterial.PublicKeyBytes, env.Serialize())
		ke2.MaskedResponse = xorResponse(conf.internal, rec.MaskingKey, ke2.MaskingNonce, clearText)

		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrEnvelopeInvalidMac)
	})
}

func cleartextCredentials(clientPublicKey, serverPublicKey, idc, ids []byte) []byte {
	if ids == nil {
		ids = serverPublicKey
	}

	if idc == nil {
		idc = clientPublicKey
	}

	return encoding.Concat3(serverPublicKey, encoding.EncodeVector(ids), encoding.EncodeVector(idc))
}

// TestClient_GenerateKE3_ErrEnvelopeInvalidMac_WrongServerPublicKey ensures any mismatch between the stored masking key and the reconstructed server key trips the MAC check, preventing swap attacks.
func TestClient_GenerateKE3_ErrEnvelopeInvalidMac_WrongServerPublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t.Fatal(err)
		}

		// Use a valid encoding but with a fake public key
		group := conf.conf.AKE.Group()
		fakepks := group.Base().Multiply(group.NewScalar().Random()).Encode()
		clearText := encoding.Concat(fakepks, record.Envelope)
		ke2.MaskedResponse = xorResponse(conf.internal, record.MaskingKey, ke2.MaskingNonce, clearText)

		expectErrors(t, func() error {
			_, _, _, err := client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrEnvelopeInvalidMac)
	})
}

// TestClient_GenerateKE3_InvalidServerPublicKey verifies that malformed server public key encodings are rejected even after envelope decryption, closing a gap where fake keys could be smuggled in.
func TestClient_GenerateKE3_InvalidServerPublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		blind := conf.conf.OPRF.Group().NewScalar().Random()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t.Fatal(err)
		}

		env, randomizedPassword, err := getEnvelope(conf.internal, blind, password, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper server public key
		badServerPublicKey := conf.getBadElement()

		ctc := cleartextCredentials(
			record.RegistrationRecord.ClientPublicKey.Encode(),
			badServerPublicKey,
			nil,
			nil,
		)
		authKey := conf.internal.KDF.Expand(
			randomizedPassword,
			encoding.SuffixString(env.Nonce, tag.AuthKey),
			conf.internal.KDF.Size(),
		)
		authTag := conf.internal.MAC.MAC(authKey, encoding.Concat(env.Nonce, ctc))
		env.AuthTag = authTag

		// Use an invalid encoding for the server public key
		clearText := encoding.Concat(badServerPublicKey, env.Serialize())
		ke2.MaskedResponse = xorResponse(conf.internal, record.MaskingKey, ke2.MaskingNonce, clearText)

		expectErrors(t, func() error {
			_, _, _, err = client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrAuthenticationInvalidServerPublicKey)
	})
}

// TestClient_GenerateKE3_InvalidKE2Mac confirms that manipulating the server MAC leads to an authentication error, proving the server’s keystream integrity protection works.
func TestClient_GenerateKE3_InvalidKE2Mac(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t.Fatal(err)
		}

		ke2.ServerMac = internal.RandomBytes(conf.internal.MAC.Size())
		expectErrors(t, func() error {
			_, _, _, err := client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication, internal.ErrServerAuthentication)
	})
}

// TestClientPRK validates the PRK derivation pipeline across KSF backends, ensuring deterministic outputs used in test vectors remain stable and interoperable.
func TestClientPRK(t *testing.T) {
	type prkTest struct {
		name          string
		input         string
		ksfSalt       string
		kdfSalt       string
		output        string
		ksfParameters []int
		ksfLength     int
		kdf           crypto.Hash
		ksf           ksf.Identifier
	}

	tests := []prkTest{
		{
			name:          "Argon2id",
			ksf:           ksf.Argon2id,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{3, 65536, 4},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "3e858a95d7fe77be3a6278dafa572f8a3a1d49a7154e3a0710d9a5a46358fd0993d958d0963cd88c0a907d105fadcb8c0702b02f8305f8f3c77204b63a93e469",
		},
		{
			name:          "Scrypt",
			ksf:           ksf.Scrypt,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{32768, 8, 1},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "a0d28223edab936f13d778636f1801c0368c2b8d990c5be3cf93d7d1f5ade9d7634a2b20b2f09ac2f1508be6741fcd2f4279ecf33d4b672991b107463016c37f",
		},
		{
			name:          "PBKDF2",
			ksf:           ksf.PBKDF2Sha512,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{10000},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "35bd30915a0564dbd160402bec5163441cc3c8c3c9ee4cf2d87f0f2e228b514cf1c18a41ce9e84b3306286cd06032b296a4a2ff487945e59fcecbab7f06b3098",
		},
		{
			name:          "Identity",
			ksf:           0,
			ksfSalt:       "ksfSalt",
			ksfLength:     32,
			ksfParameters: []int{1, 2},
			kdf:           crypto.SHA512,
			kdfSalt:       "kdfSalt",
			input:         "password",
			output:        "deba3102d5ddf4b833ff43d3d2f3fb77b9514652bb6ce7b985a091478a6c8ecaedb0354d72284202c3de9f358cba8885326403b9738835ae86b6a49fec25ab38",
		},
	}

	for _, ksfTest := range tests {
		t.Run(ksfTest.name, func(t *testing.T) {
			input := []byte(ksfTest.input)
			stretcher := ksf2.NewKSF(ksfTest.ksf)
			stretcher.Parameterize(ksfTest.ksfParameters...)
			stretched := stretcher.Harden(input, []byte(ksfTest.ksfSalt), ksfTest.ksfLength)

			extract := internal.NewKDF(ksfTest.kdf)
			output := hex.EncodeToString(extract.Extract([]byte(ksfTest.kdfSalt), encoding.Concat(input, stretched)))

			if output != ksfTest.output {
				t.Errorf("got %q, want %q", output, ksfTest.output)
			}
		})
	}
}
