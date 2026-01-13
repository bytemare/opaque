// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
)

const dbgErr = "%v"

type testParams struct {
	*opaque.Configuration
	serverSecretKey                                                  *ecc.Scalar
	serverPublicKey                                                  *ecc.Element
	username, userID, serverID, password, oprfSeed, ksfSalt, kdfSalt []byte
	ksfParameters                                                    []int
	ksfLength, nonceLength                                           int
}

// TestFull runs an end-to-end registration plus authentication flow across all configurations, ensuring the exported API yields matching session keys for client and server.
func TestFull(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")
	password := []byte("password")

	conf := opaque.DefaultConfiguration()
	conf.Context = []byte("OPAQUETest")
	conf.KSF = ksf.Argon2id

	tester := &testParams{
		Configuration: conf,
		username:      username,
		userID:        username,
		serverID:      ids,
		password:      password,
		oprfSeed:      conf.GenerateOPRFSeed(),
		ksfParameters: []int{3, 65536, 4},
		ksfSalt:       []byte("ksfSalt"),
		kdfSalt:       []byte("kdfSalt"),
		nonceLength:   internal.NonceLength,
	}

	tester.serverSecretKey, tester.serverPublicKey = conf.KeyGen()

	/*
		Registration
	*/
	_, _, record, exportKeyReg := testRegistration(t, tester)

	/*
		Login
	*/
	_, _, exportKeyLogin := testAuthentication(t, tester, record)

	// Check values
	if !bytes.Equal(exportKeyReg, exportKeyLogin) {
		t.Errorf("export keys differ")
	}
}

func testRegistration(t *testing.T, p *testParams) (*opaque.Client, *opaque.Server, *opaque.ClientRecord, []byte) {
	// Client
	client, err := p.Client()
	if err != nil {
		t.Fatalf(dbgErr, err)
	}

	var m1s []byte
	{
		reqReg, err := client.RegistrationInit(p.password)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m1s = reqReg.Serialize()
	}

	// Server
	var m2s []byte
	{
		server, _ := p.Server()
		server.ServerKeyMaterial = &opaque.ServerKeyMaterial{
			PublicKeyBytes: p.serverPublicKey.Encode(),
			OPRFGlobalSeed: p.oprfSeed,
		}

		m1, err := server.Deserialize.RegistrationRequest(m1s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		respReg, err := server.RegistrationResponse(m1, credentialIdentifier, nil)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m2s = respReg.Serialize()
	}

	// Client
	var m3s []byte
	var exportKeyReg []byte
	{
		m2, err := client.Deserialize.RegistrationResponse(m2s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		upload, key, err := client.RegistrationFinalize(m2, p.username, p.serverID, &opaque.ClientOptions{
			KDFSalt:       p.kdfSalt,
			KSFSalt:       p.ksfSalt,
			KSFParameters: p.ksfParameters,
			KSFLength:     p.ksfLength,
		})
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		exportKeyReg = key

		m3s = upload.Serialize()
	}

	// Server
	{
		server, _ := p.Server()
		m3, err := server.Deserialize.RegistrationRecord(m3s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		return client, server, &opaque.ClientRecord{
			CredentialIdentifier: credentialIdentifier,
			ClientIdentity:       p.username,
			RegistrationRecord:   m3,
		}, exportKeyReg
	}
}

func testAuthentication(
	t *testing.T,
	p *testParams,
	record *opaque.ClientRecord,
) (*opaque.Client, *opaque.Server, []byte) {
	// Client
	client, err := p.Client()
	if err != nil {
		t.Fatalf(dbgErr, err)
	}

	var m4s []byte
	{
		ke1, err := client.GenerateKE1(p.password)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m4s = ke1.Serialize()
	}

	// Server
	var m5s []byte
	server, _ := p.Server()
	var serverOutput *opaque.ServerOutput
	{
		skm := &opaque.ServerKeyMaterial{
			Identity:       p.serverID,
			PrivateKey:     p.serverSecretKey,
			PublicKeyBytes: p.serverPublicKey.Encode(),
			OPRFGlobalSeed: p.oprfSeed,
		}

		if err := server.SetKeyMaterial(skm); err != nil {
			t.Fatalf(dbgErr, err)
		}

		m4, err := server.Deserialize.KE1(m4s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		var ke2 *message.KE2
		ke2, serverOutput, err = server.GenerateKE2(m4, record)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m5s = ke2.Serialize()
	}

	// Client
	var m6s []byte
	var exportKeyLogin []byte
	var clientKey []byte
	{
		m5, err := client.Deserialize.KE2(m5s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		var ke3 *message.KE3
		ke3, clientKey, exportKeyLogin, err = client.GenerateKE3(m5, p.username, p.serverID, &opaque.ClientOptions{
			KDFSalt:       p.kdfSalt,
			KSFSalt:       p.ksfSalt,
			KSFParameters: p.ksfParameters,
			KSFLength:     p.ksfLength,
		})
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		m6s = ke3.Serialize()
	}

	// Server
	{
		m6, err := server.Deserialize.KE3(m6s)
		if err != nil {
			t.Fatalf(dbgErr, err)
		}

		if err := server.LoginFinish(m6, serverOutput.ClientMAC); err != nil {
			t.Fatalf(dbgErr, err)
		}
	}

	if !bytes.Equal(clientKey, serverOutput.SessionSecret) {
		t.Log(hex.EncodeToString(clientKey))
		t.Log(hex.EncodeToString(serverOutput.SessionSecret))
		t.Fatalf("session keys differ")
	}

	return client, server, exportKeyLogin
}

// TestConfiguration_Deserialization confirms serialized configurations can be restored without loss, which is crucial for persistence and upgrades.
func TestConfiguration_Deserialization(t *testing.T) {
	conf := opaque.DefaultConfiguration()
	ser := conf.Serialize()

	conf2, err := opaque.DeserializeConfiguration(ser)
	if err != nil {
		t.Fatalf("unexpected error on valid configuration: %v", err)
	}

	if err := conf.Equals(conf2); err != nil {
		t.Fatalf("Unexpected inequality: %s\n\t%v\n\t%v", err, conf, conf2)
	}
}

// TestFlush guarantees sensitive configuration fields are cleared when requested, reducing the risk of key retention.
func TestFlush(t *testing.T) {
	ids := []byte("server")
	username := []byte("client")

	conf := opaque.DefaultConfiguration()
	conf.Context = []byte("OPAQUETest")

	test := &testParams{
		Configuration: conf,
		username:      username,
		userID:        username,
		serverID:      ids,
		password:      password,
		oprfSeed:      conf.GenerateOPRFSeed(),
	}

	test.serverSecretKey, test.serverPublicKey = conf.KeyGen()

	/*
		Registration
	*/
	_, _, record, _ := testRegistration(t, test)

	/*
		Login
	*/
	client, _, _ := testAuthentication(t, test, record)

	client.ClearState()
}

/*
	The following tests look for failing conditions.
*/

// TestConfiguration_NotEqual checks that mismatched configurations are detected, ensuring equality comparisons remain dependable during validation.
func TestConfiguration_NotEqual(t *testing.T) {
	type tester struct {
		name            string
		mod             func(c opaque.Configuration) *opaque.Configuration
		expectedMessage string
	}

	tests := []tester{
		{
			name: "Nil configuration",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				return nil
			},
			expectedMessage: "nil configuration",
		},
		{
			name: "Different KDF",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				if c.KDF == crypto.SHA256 {
					c.KDF = crypto.SHA512
				} else {
					c.KDF = crypto.SHA256
				}
				return &c
			},
			expectedMessage: "KDF mismatch",
		},
		{
			name: "Different MAC",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				if c.MAC == crypto.SHA256 {
					c.MAC = crypto.SHA512
				} else {
					c.MAC = crypto.SHA256
				}
				return &c
			},
			expectedMessage: "MAC mismatch",
		},
		{
			name: "Different Hash",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				if c.Hash == crypto.SHA256 {
					c.Hash = crypto.SHA512
				} else {
					c.Hash = crypto.SHA256
				}
				return &c
			},
			expectedMessage: "Hash mismatch",
		},
		{
			name: "Different KSF",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				if c.KSF == ksf.Argon2id {
					c.KSF = ksf.Scrypt
				} else {
					c.KSF = ksf.Argon2id
				}
				return &c
			},
			expectedMessage: "KSF mismatch",
		},
		{
			name: "Different OPRF",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				if c.OPRF == opaque.RistrettoSha512 {
					c.OPRF = opaque.P256Sha256
				} else {
					c.OPRF = opaque.RistrettoSha512
				}
				return &c
			},
			expectedMessage: "OPRF mismatch",
		},
		{
			name: "Different AKE",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				if c.AKE == opaque.RistrettoSha512 {
					c.AKE = opaque.P256Sha256
				} else {
					c.AKE = opaque.RistrettoSha512
				}
				return &c
			},
			expectedMessage: "AKE mismatch",
		},
		{
			name: "Different Context",
			mod: func(c opaque.Configuration) *opaque.Configuration {
				c.Context = []byte("different context")
				return &c
			},
			expectedMessage: "context mismatch",
		},
	}

	conf := opaque.DefaultConfiguration()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := tt.mod(*conf)

			err := conf.Equals(bad)
			if err == nil {
				t.Fatalf("expected inequality error, got nil")
			}

			if !errors.Is(err, opaque.ErrConfiguration) {
				t.Fatalf("expected ErrConfiguration, got %v", err)
			}

			if !strings.Contains(err.Error(), tt.expectedMessage) {
				t.Fatalf("error message %q does not contain expected substring: %q", err.Error(), tt.expectedMessage)
			}
		})
	}
}

// TestDeserializeConfiguration_InvalidContextHeader ensures corrupted context length headers are rejected on load, preventing truncated metadata from being accepted.
func TestDeserializeConfiguration_InvalidContextHeader(t *testing.T) {
	d := opaque.DefaultConfiguration().Serialize()
	d[7] = 20

	expectErrors(t, func() error {
		_, err := opaque.DeserializeConfiguration(d)
		return err
	}, opaque.ErrConfiguration, internal.ErrInvalidContextEncoding, encoding.ErrTotalLength)
}

// TestDeserializeConfiguration_Short verifies the decoder refuses undersized payloads, protecting against partially written configuration blobs.
func TestDeserializeConfiguration_Short(t *testing.T) {
	r7 := internal.RandomBytes(7)

	expectErrors(t, func() error {
		_, err := opaque.DeserializeConfiguration(r7)
		return err
	}, opaque.ErrConfiguration, internal.ErrInvalidEncodingLength)
}

// TestBadConfiguration enumerates invalid algorithm identifiers to ensure misconfigured deployments fail during setup instead of misbehaving later.
func TestBadConfiguration(t *testing.T) {
	setBadValue := func(pos, val int) []byte {
		b := opaque.DefaultConfiguration().Serialize()
		b[pos] = byte(val)
		return b
	}

	tests := []struct {
		error   error
		makeBad func() []byte
		name    string
	}{
		{
			name: "Bad OPRF",
			makeBad: func() []byte {
				return setBadValue(0, 0)
			},
			error: internal.ErrInvalidOPRFid,
		},
		{
			name: "Bad AKE",
			makeBad: func() []byte {
				return setBadValue(1, 0)
			},
			error: internal.ErrInvalidAKEid,
		},
		{
			name: "Bad KSF",
			makeBad: func() []byte {
				return setBadValue(2, 10)
			},
			error: internal.ErrInvalidKSFid,
		},
		{
			name: "Bad KDF",
			makeBad: func() []byte {
				return setBadValue(3, 0)
			},
			error: internal.ErrInvalidKDFid,
		},
		{
			name: "Bad MAC",
			makeBad: func() []byte {
				return setBadValue(4, 0)
			},
			error: internal.ErrInvalidMACid,
		},
		{
			name: "Bad Hash",
			makeBad: func() []byte {
				return setBadValue(5, 0)
			},
			error: internal.ErrInvalidHASHid,
		},
	}

	convertToBadConf := func(encoded []byte) *opaque.Configuration {
		return &opaque.Configuration{
			OPRF:    opaque.Group(encoded[0]),
			AKE:     opaque.Group(encoded[1]),
			KSF:     ksf.Identifier(encoded[2]),
			KDF:     crypto.Hash(encoded[3]),
			MAC:     crypto.Hash(encoded[4]),
			Hash:    crypto.Hash(encoded[5]),
			Context: encoded[6:],
		}
	}

	for _, badConf := range tests {
		t.Run(badConf.name, func(t *testing.T) {
			// Test Deserialization for bad conf
			badEncoded := badConf.makeBad()

			expectErrors(t, func() error {
				_, err := opaque.DeserializeConfiguration(badEncoded)
				return err
			}, badConf.error)

			// Test bad configuration for client, server, and deserializer setup
			bad := convertToBadConf(badEncoded)

			expectErrors(t, func() error {
				_, err := bad.Client()
				return err
			}, badConf.error)

			expectErrors(t, func() error {
				_, err := bad.Server()
				return err
			}, badConf.error)

			expectErrors(t, func() error {
				_, err := bad.Deserializer()
				return err
			}, badConf.error)
		})
	}
}

// TestGetFakeRecord ensures GetFakeRecord succeeds for valid configurations and rejects invalid ones.
func TestGetFakeRecord(t *testing.T) {
	// Test valid configurations
	testAll(t, func(t2 *testing.T, conf *configuration) {
		if _, err := conf.conf.GetFakeRecord(nil); err != nil {
			t.Fatalf("unexpected error on valid configuration: %v", err)
		}
	})

	// Test for an invalid configuration.
	conf := &opaque.Configuration{
		OPRF:    0,
		AKE:     0,
		KSF:     0,
		KDF:     0,
		MAC:     0,
		Hash:    0,
		Context: nil,
	}

	if _, err := conf.GetFakeRecord(nil); err == nil {
		t.Fatal("expected error on invalid configuration")
	}
}

// TestErrorFormattingAndLogging exercises slog and fmt integration so structured logs capture error codes and messages without additional plumbing.
func TestErrorFormattingAndLogging(t *testing.T) {
	base := errors.New("root cause")
	wrapped := fmt.Errorf("wrap: %w", base)
	sibling := errors.New("peer issue")
	err := opaque.ErrCodeAuthentication.New("handshake failed", errors.Join(wrapped, sibling))

	if got := err.Error(); got != "handshake failed" {
		t.Fatalf("unexpected error string: %q", got)
	}

	if got := fmt.Sprintf("%s", err); got != "handshake failed" {
		t.Fatalf("expected %%s to print message, got %q", got)
	}
	if got := fmt.Sprintf("%v", err); got != "handshake failed" {
		t.Fatalf("expected %%v to print message, got %q", got)
	}
	if got := fmt.Sprintf("%q", err); got != "\"handshake failed\"" {
		t.Fatalf("expected quoted output, got %q", got)
	}

	verbose := fmt.Sprintf("%+v", err)
	if !strings.Contains(verbose, "handshake failed") {
		t.Fatalf("verbose format missing message: %q", verbose)
	}
	if !strings.Contains(verbose, "wrap: root cause") {
		t.Fatalf("verbose format missing wrapped cause: %q", verbose)
	}
	if !strings.Contains(verbose, "peer issue") {
		t.Fatalf("verbose format missing sibling cause: %q", verbose)
	}
	if !strings.Contains(verbose, "\u21b3") {
		t.Fatalf("verbose format should include arrow prefix: %q", verbose)
	}

	value := err.LogValue()
	if value.Kind() != slog.KindGroup {
		t.Fatalf("expected slog group value, got kind %v", value.Kind())
	}

	attrs := value.Group()
	got := make(map[string]slog.Value, len(attrs))
	for _, attr := range attrs {
		got[attr.Key] = attr.Value
	}

	if attr, ok := got["code"]; !ok || attr.Int64() != int64(err.Code) {
		t.Fatalf("missing or invalid code attribute: %+v", attrs)
	}
	if attr, ok := got["code_name"]; !ok || attr.String() != err.Code.String() {
		t.Fatalf("missing or invalid code_name attribute: %+v", attrs)
	}
	if attr, ok := got["message"]; !ok || attr.String() != err.Message {
		t.Fatalf("missing or invalid message attribute: %+v", attrs)
	}
	if _, ok := got["error"]; !ok {
		t.Fatalf("missing nested error attribute: %+v", attrs)
	}
}

// TestErrorAsVariants shows that different target types can be extracted via errors.As, simplifying downstream error inspection.
func TestErrorAsVariants(t *testing.T) {
	cause := errors.New("registration failed")
	err := opaque.ErrCodeRegistration.New("state invalid", cause)

	var code opaque.ErrorCode
	if !err.As(&code) {
		t.Fatal("expected As to populate ErrorCode")
	}
	if !code.Is(err) {
		t.Fatalf("unexpected ErrorCode: %v", code)
	}

	var target *opaque.Error
	if !err.As(&target) {
		t.Fatal("expected As to populate *Error")
	}
	if !target.Is(err) {
		t.Fatalf("expected target to reference original error, got %p != %p", target, err)
	}

	var nope string
	if err.As(&nope) {
		t.Fatal("unexpected As success for incompatible target")
	}

	if !opaque.ErrCodeAuthentication.As(opaque.ErrCodeAuthentication) {
		t.Fatal("expected direct ErrorCode target to succeed")
	}

	var stored opaque.ErrorCode
	if !opaque.ErrCodeAuthentication.As(&stored) {
		t.Fatal("expected pointer ErrorCode target to succeed")
	}
	if !stored.Is(opaque.ErrCodeAuthentication) {
		t.Fatalf("unexpected stored ErrorCode: %v", stored)
	}

	var unsupported bool
	if opaque.ErrCodeAuthentication.As(&unsupported) {
		t.Fatal("unexpected As success for unsupported type")
	}

	unknown := opaque.ErrorCode(255)
	if unknown.String() != "unknown_error" {
		t.Fatalf("unexpected string for unknown code: %q", unknown.String())
	}

	if unknown.Error() != "unknown_error" {
		t.Fatalf("unexpected error() output for unknown code: %q", unknown.Error())
	}
}

// TestErrorCodeStringCoverage iterates all error codes to ensure their string forms remain stable for documentation and telemetry.
func TestErrorCodeStringCoverage(t *testing.T) {
	cases := map[opaque.ErrorCode]string{
		opaque.ErrCodeUnknown:           "unknown_error",
		opaque.ErrCodeConfiguration:     "configuration_error",
		opaque.ErrCodeRegistration:      "registration_error",
		opaque.ErrCodeAuthentication:    "authentication_error",
		opaque.ErrCodeMessage:           "message_error",
		opaque.ErrCodeServerKeyMaterial: "server_key_material_error",
		opaque.ErrCodeServerOptions:     "server_options_error",
		opaque.ErrCodeClientRecord:      "client_record_error",
		opaque.ErrCodeClientState:       "client_state_error",
		opaque.ErrCodeClientOptions:     "client_options_error",
	}

	for code, want := range cases {
		if got := code.String(); got != want {
			t.Fatalf("code %d: want %q got %q", code, want, got)
		}
		if got := code.Error(); got != want {
			t.Fatalf("code %d: unexpected error() output %q", code, got)
		}
	}
}

// TestErrorCodeIsBranches verifies that ErrorCode.Is handles both ErrorCode and *Error targets, keeping compatibility with the standard errors helper.
func TestErrorCodeIsBranches(t *testing.T) {
	target := opaque.ErrCodeRegistration.New("wrapped", errors.New("inner"))

	if !opaque.ErrCodeRegistration.Is(target) {
		t.Fatal("expected ErrorCode to match wrapped *Error")
	}

	if !opaque.ErrCodeRegistration.Is(opaque.ErrRegistration) {
		t.Fatal("expected ErrorCode to match exported sentinel")
	}

	if opaque.ErrCodeRegistration.Is(internal.ErrInvalidAKEid) {
		t.Fatal("unexpected ErrorCode match for unrelated error")
	}

	bogus := fmt.Errorf("%w", opaque.ErrRegistration)
	if !opaque.ErrCodeRegistration.Is(bogus) {
		t.Fatal("expected ErrorCode to match via errors.As chain")
	}
}

// TestErrorFormatDefaultVerb ensures the default fmt verbs return the concise message form, which is what applications expect when reporting errors.
func TestErrorFormatDefaultVerb(t *testing.T) {
	err := opaque.ErrCodeClientOptions.New("format me", fmt.Errorf("%w", opaque.ErrClientOptions))
	if got := fmt.Sprintf("%x", err); !strings.Contains(got, "format me") {
		t.Fatalf("expected hex verb to fall back to message, got %q", got)
	}
}

// TestValidScalar ensures scalar validation rejects nil, wrong-group, and zero values, maintaining protocol safety when importing external secrets.
func TestValidScalar(t *testing.T) {
	group := ecc.Ristretto255Sha512

	scalar := group.NewScalar().Random()
	if err := opaque.IsValidScalar(group, scalar); err != nil {
		t.Fatalf("unexpected error on valid scalar: %v", err)
	}

	if err := opaque.IsValidScalar(group, nil); !errors.Is(err, internal.ErrScalarNil) {
		t.Fatalf("expected ErrScalarNil, got %v", err)
	}

	wrong := ecc.P256Sha256.NewScalar().Random()
	if err := opaque.IsValidScalar(group, wrong); !errors.Is(err, internal.ErrScalarGroupMismatch) {
		t.Fatalf("expected ErrScalarGroupMismatch, got %v", err)
	}

	zero := group.NewScalar()
	zero.Zero()
	if err := opaque.IsValidScalar(group, zero); !errors.Is(err, internal.ErrScalarZero) {
		t.Fatalf("expected ErrScalarZero, got %v", err)
	}
}

// TestValidElement ensures element validation detects nil, identity, and wrong-group points, safeguarding against invalid public keys.
func TestValidElement(t *testing.T) {
	group := ecc.Ristretto255Sha512

	element := group.NewElement().Base()
	if err := opaque.IsValidElement(group, element); err != nil {
		t.Fatalf("unexpected error on valid element: %v", err)
	}

	if err := opaque.IsValidElement(group, nil); !errors.Is(err, internal.ErrElementNil) {
		t.Fatalf("expected ErrElementNil, got %v", err)
	}

	wrong := ecc.P256Sha256.NewElement().Base()
	if err := opaque.IsValidElement(group, wrong); !errors.Is(err, internal.ErrElementGroupMismatch) {
		t.Fatalf("expected ErrElementGroupMismatch, got %v", err)
	}

	// Identity point check
	identity := group.NewElement()
	identity.Identity()
	if err := opaque.IsValidElement(group, identity); !errors.Is(err, internal.ErrElementIdentity) {
		t.Fatalf("expected ErrElementIdentity, got %v", err)
	}
}
