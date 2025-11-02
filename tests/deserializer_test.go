// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
)

const testErrValidConf = "unexpected error on valid configuration: %v"

var errInvalidMessageLength = internal.ErrInvalidMessageLength

func getDeserializer(t *testing.T, c *opaque.Configuration) *opaque.Deserializer {
	t.Helper()

	d, err := c.Deserializer()
	if err != nil {
		t.Fatal(err)
	}

	return d
}

/*
	Message Deserialization
*/

// TestDeserializer_New ensures constructing a deserializer with a configuration succeeds and protects against unsupported suites, forming the base for all parsing helpers.
func TestDeserializer_New(t *testing.T) {
	// Test valid configurations
	testAll(t, func(t2 *testing.T, conf *configuration) {
		if _, err := conf.conf.Deserializer(); err != nil {
			t.Fatalf(testErrValidConf, err)
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

	if _, err := conf.Deserializer(); err == nil {
		t.Fatal("expected error on invalid configuration")
	}
}

type deserializerErrorTest struct {
	method string
	name   string
	input  []byte
	errors []error
}

func getDeserializerMethodTopError(method string) error {
	switch method {
	case "RegistrationRequest":
		return opaque.ErrRegistrationRequest
	case "RegistrationResponse":
		return opaque.ErrRegistrationResponse
	case "RegistrationRecord":
		return opaque.ErrRegistrationRecord
	case "KE1":
		return opaque.ErrKE1
	case "KE2":
		return opaque.ErrKE2
	case "KE3":
		return opaque.ErrKE3
	default:
		panic("unknown deserializer method: " + method)
	}
}

func getDeserializerMethod(method string) func(d *opaque.Deserializer, input []byte) error {
	switch method {
	case "RegistrationRequest":
		return func(d *opaque.Deserializer, input []byte) error {
			_, err := d.RegistrationRequest(input)
			return err
		}
	case "RegistrationResponse":
		return func(d *opaque.Deserializer, input []byte) error {
			_, err := d.RegistrationResponse(input)
			return err
		}
	case "RegistrationRecord":
		return func(d *opaque.Deserializer, input []byte) error {
			_, err := d.RegistrationRecord(input)
			return err
		}
	case "KE1":
		return func(d *opaque.Deserializer, input []byte) error {
			_, err := d.KE1(input)
			return err
		}
	case "KE2":
		return func(d *opaque.Deserializer, input []byte) error {
			_, err := d.KE2(input)
			return err
		}
	case "KE3":
		return func(d *opaque.Deserializer, input []byte) error {
			_, err := d.KE3(input)
			return err
		}
	default:
		panic("unknown deserializer method: " + method)
	}
}

func generateDeserializerErrorTestNilInput(method string) deserializerErrorTest {
	return generateDeserializerErrorTest(method, "nil input", nil, errInvalidMessageLength)
}

func generateDeserializerErrorTestEmptyInput(method string) deserializerErrorTest {
	return generateDeserializerErrorTest(method, "empty input", []byte{}, errInvalidMessageLength)
}

func generateDeserializerErrorTestInputTooShort(method string) deserializerErrorTest {
	// should be too short for all suites
	return generateDeserializerErrorTest(method, "input too short", internal.RandomBytes(30), errInvalidMessageLength)
}

func generateDeserializerErrorTestInputTooLong(method string) deserializerErrorTest {
	// should be too long for all suites
	return generateDeserializerErrorTest(method, "input too long", internal.RandomBytes(100), errInvalidMessageLength)
}

func generateDeserializerErrorTest(method, name string, input []byte, errors ...error) deserializerErrorTest {
	return deserializerErrorTest{
		method: method,
		name:   fmt.Sprintf("%s:%s", method, name),
		input:  input,
		errors: append([]error{getDeserializerMethodTopError(method)}, errors...),
	}
}

// TestDeserializer_RegistrationRequest_Errors validates that malformed registration requests are rejected during decoding, preventing bogus client material from entering the protocol.
func TestDeserializer_RegistrationRequest_Errors(t *testing.T) {
	method := "RegistrationRequest"
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		d := getDeserializer(t, c)

		tests := []deserializerErrorTest{
			generateDeserializerErrorTestNilInput(method),
			generateDeserializerErrorTestEmptyInput(method),
			generateDeserializerErrorTestInputTooShort(method),
			generateDeserializerErrorTestInputTooLong(method),
			generateDeserializerErrorTest(method, "invalid data",
				conf.getBadElement(),
				opaque.ErrRegistrationRequest, internal.ErrInvalidBlindedMessage),
			generateDeserializerErrorTest(method, "blinded element is zero",
				conf.conf.OPRF.Group().NewElement().Encode(),
				opaque.ErrRegistrationRequest, internal.ErrInvalidBlindedMessage),
		}

		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t2 *testing.T) {
				f := getDeserializerMethod(te.method)

				expectErrors(t, func() error {
					return f(d, te.input)
				}, te.errors...)
			})
		}
	})
}

// TestDeserializer_RegistrationResponse_Errors checks that invalid registration responses fail early, helping clients avoid using corrupted server outputs.
func TestDeserializer_RegistrationResponse_Errors(t *testing.T) {
	method := "RegistrationResponse"
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		d := getDeserializer(t, c)

		badElement := conf.getBadElement()
		randomElement := conf.getValidElementBytes()
		zeroElement := c.OPRF.Group().NewElement().Encode()

		tests := []deserializerErrorTest{
			generateDeserializerErrorTestNilInput(method),
			generateDeserializerErrorTestEmptyInput(method),
			generateDeserializerErrorTestInputTooShort(method),
			generateDeserializerErrorTestInputTooLong(method),
			generateDeserializerErrorTest(method, "invalid data",
				encoding.Concat(badElement, randomElement),
				opaque.ErrRegistrationResponse, internal.ErrInvalidEvaluatedMessage),
			generateDeserializerErrorTest(method, "evaluate zero element",
				encoding.Concat(zeroElement, randomElement),
				opaque.ErrRegistrationResponse, internal.ErrInvalidEvaluatedMessage),
			generateDeserializerErrorTest(method, "invalid server public key",
				encoding.Concat(randomElement, badElement),
				opaque.ErrRegistrationResponse, internal.ErrInvalidServerPublicKey),
			generateDeserializerErrorTest(method, "server public key is zero",
				encoding.Concat(randomElement, zeroElement),
				opaque.ErrRegistrationResponse, internal.ErrInvalidServerPublicKey),
		}

		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t2 *testing.T) {
				f := getDeserializerMethod(te.method)

				expectErrors(t, func() error {
					return f(d, te.input)
				}, te.errors...)
			})
		}
	})
}

// TestDeserializer_RegistrationRecord_Errors confirms storage records are thoroughly validated before use, preserving envelope integrity and key consistency.
func TestDeserializer_RegistrationRecord_Errors(t *testing.T) {
	method := "RegistrationRecord"
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		d := getDeserializer(t, c)

		badElement := conf.getBadElement()
		randomElement := conf.getValidElementBytes()
		zeroElement := c.OPRF.Group().NewElement().Encode()
		okMaskingKey := internal.RandomBytes(c.Hash.Size())
		okEnvelope := internal.RandomBytes(conf.internal.EnvelopeSize)

		makeBadRecord := func(pk, maskingKey, envelope []byte) []byte {
			return encoding.Concat3(pk, maskingKey, envelope)
		}

		recordBadPublicKey := makeBadRecord(badElement, okMaskingKey, okEnvelope)
		recordBadPublicKeyZero := makeBadRecord(zeroElement, okMaskingKey, okEnvelope)
		recordMaskingKeyZeros := makeBadRecord(randomElement, make([]byte, c.Hash.Size()), okEnvelope)

		tests := []deserializerErrorTest{
			generateDeserializerErrorTestNilInput(method),
			generateDeserializerErrorTestEmptyInput(method),
			generateDeserializerErrorTestInputTooShort(method),
			generateDeserializerErrorTestInputTooLong(method),
			generateDeserializerErrorTest(method, "invalid client public key",
				recordBadPublicKey,
				opaque.ErrRegistrationRecord, internal.ErrInvalidClientPublicKey),
			generateDeserializerErrorTest(method, "server public key is zero",
				recordBadPublicKeyZero,
				opaque.ErrRegistrationRecord, internal.ErrInvalidClientPublicKey),
			generateDeserializerErrorTest(method, "masking key is all zeros",
				recordMaskingKeyZeros,
				opaque.ErrRegistrationRecord, internal.ErrInvalidMaskingKey, internal.ErrSliceIsAllZeros),
		}
		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t2 *testing.T) {
				f := getDeserializerMethod(te.method)

				expectErrors(t, func() error {
					return f(d, te.input)
				}, te.errors...)
			})
		}
	})
}

// TestDeserializer_KE1_Errors ensures malformed KE1 messages are caught during parsing, so servers never operate on invalid key shares or nonces.
func TestDeserializer_KE1_Errors(t *testing.T) {
	method := "KE1"
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		d := getDeserializer(t, c)

		badElement := conf.getBadElement()
		randomElement := conf.getValidElementBytes()
		zeroElement := c.OPRF.Group().NewElement().Encode()

		tests := []deserializerErrorTest{
			generateDeserializerErrorTestNilInput(method),
			generateDeserializerErrorTestEmptyInput(method),
			generateDeserializerErrorTestInputTooShort(method),
			generateDeserializerErrorTestInputTooLong(method),
			generateDeserializerErrorTest(method, "invalid blinded message",
				encoding.Concat(badElement, internal.RandomBytes(conf.internal.NonceLen+c.AKE.Group().ElementLength())),
				opaque.ErrKE1, internal.ErrInvalidBlindedMessage),
			generateDeserializerErrorTest(
				method,
				"blinded message is zero",
				encoding.Concat(
					zeroElement,
					internal.RandomBytes(conf.internal.NonceLen+c.AKE.Group().ElementLength()),
				),
				opaque.ErrKE1,
				internal.ErrInvalidBlindedMessage,
			),
			generateDeserializerErrorTest(method, "nonce is all zeros",
				encoding.Concat3(randomElement, make([]byte, conf.internal.NonceLen), randomElement),
				opaque.ErrKE1, internal.ErrMissingNonce, internal.ErrSliceIsAllZeros),
			generateDeserializerErrorTest(method, "invalid client key share",
				encoding.Concat3(randomElement, internal.RandomBytes(conf.internal.NonceLen), badElement),
				opaque.ErrKE1, internal.ErrInvalidClientKeyShare),
			generateDeserializerErrorTest(method, "client key share is zero",
				encoding.Concat3(randomElement, internal.RandomBytes(conf.internal.NonceLen), zeroElement),
				opaque.ErrKE1, internal.ErrInvalidClientKeyShare),
		}

		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t2 *testing.T) {
				f := getDeserializerMethod(te.method)

				expectErrors(t, func() error {
					return f(d, te.input)
				}, te.errors...)
			})
		}
	})
}

//func TestScalar(t *testing.T) {
//	h := "25e852079d01b412ca9df1a8dcaefa99f52c757d69242d2edde02317a2d8760f02"
//
//	sb, err := hex.DecodeString(h)
//	if err != nil {
//		t.Fatalf("failed to decode hex string: %v", err)
//	}
//
//	g := group.Ristretto255Sha512
//
//	s := g.NewScalar()
//	if err := s.Decode(sb); err != nil {
//		t.Fatalf("failed to decode scalar: %v", err)
//	}
//	t.Logf("Scalar: %s", s.Hex())
//}

// TestDeserializer_KE2_Errors enumerates bad KE2 payloads, reinforcing that clients decline tampered server responses before decrypting envelopes.
func TestDeserializer_KE2_Errors(t *testing.T) {
	method := "KE2"
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		d := getDeserializer(t, c)

		badElement := conf.getBadElement()
		okElement := conf.getValidElementBytes()
		zeroElement := c.OPRF.Group().NewElement().Encode()
		okMaskingNonce := internal.RandomBytes(conf.internal.NonceLen)
		okMaskedResponse := internal.RandomBytes(conf.internal.Group.ElementLength() + conf.internal.EnvelopeSize)
		okServerNonce := internal.RandomBytes(conf.internal.NonceLen)
		okServerMac := internal.RandomBytes(c.MAC.Size())

		makeBadKe2 := func(evaluated, maskingNonce, maskedResponse, serverNonce, pks, serverMac []byte) []byte {
			return encoding.Concatenate(evaluated, maskingNonce, maskedResponse, serverNonce, pks, serverMac)
		}

		ke2BadEvaluatedMessage := makeBadKe2(
			badElement,
			okMaskingNonce,
			okMaskedResponse,
			okServerNonce,
			okElement,
			okServerMac,
		)
		ke2BadEvaluatedMessageZero := makeBadKe2(
			zeroElement,
			okMaskingNonce,
			okMaskedResponse,
			okServerNonce,
			okElement,
			okServerMac,
		)
		ke2BadMaskingNonce := makeBadKe2(
			okElement,
			make([]byte, conf.internal.NonceLen),
			okMaskedResponse,
			okServerNonce,
			okElement,
			okServerMac,
		)
		ke2BadMaskedResponse := makeBadKe2(
			okElement,
			okMaskingNonce,
			make([]byte, conf.internal.Group.ElementLength()+conf.internal.EnvelopeSize),
			okServerNonce,
			okElement,
			okServerMac,
		)
		ke2BadServerKeyShare := makeBadKe2(
			okElement,
			okMaskingNonce,
			okMaskedResponse,
			okServerNonce,
			badElement,
			okServerMac,
		)
		ke2BadServerKeyShareZero := makeBadKe2(
			okElement,
			okMaskingNonce,
			okMaskedResponse,
			okServerNonce,
			zeroElement,
			okServerMac,
		)
		ke2BadServerNonce := makeBadKe2(
			okElement,
			okMaskingNonce,
			okMaskedResponse,
			make([]byte, conf.internal.NonceLen),
			okElement,
			okServerMac,
		)
		ke2BadServerMac := makeBadKe2(
			okElement,
			okMaskingNonce,
			okMaskedResponse,
			okServerNonce,
			okElement,
			make([]byte, c.MAC.Size()),
		)

		tests := []deserializerErrorTest{
			generateDeserializerErrorTestNilInput(method),
			generateDeserializerErrorTestEmptyInput(method),
			generateDeserializerErrorTestInputTooShort(method),
			generateDeserializerErrorTestInputTooLong(method),
			generateDeserializerErrorTest(method, "invalid evaluated message",
				ke2BadEvaluatedMessage,
				opaque.ErrKE2, internal.ErrInvalidEvaluatedMessage),
			generateDeserializerErrorTest(method, "blinded message is zero",
				ke2BadEvaluatedMessageZero,
				opaque.ErrKE2, internal.ErrInvalidEvaluatedMessage),
			generateDeserializerErrorTest(
				method,
				"masking nonce is all zeros",
				ke2BadMaskingNonce,
				opaque.ErrKE2,
				internal.ErrCredentialResponseInvalid,
				internal.ErrCredentialResponseNoMaskingNonce,
				internal.ErrSliceIsAllZeros,
			),
			generateDeserializerErrorTest(
				method,
				"masked response is all zeros",
				ke2BadMaskedResponse,
				opaque.ErrKE2,
				internal.ErrCredentialResponseInvalid,
				internal.ErrCredentialResponseInvalidMaskedResponse,
				internal.ErrSliceIsAllZeros,
			),
			generateDeserializerErrorTest(method, "invalid server key share",
				ke2BadServerKeyShare,
				opaque.ErrKE2, internal.ErrInvalidServerKeyShare),
			generateDeserializerErrorTest(method, "server key share is zero",
				ke2BadServerKeyShareZero,
				opaque.ErrKE2, internal.ErrInvalidServerKeyShare),
			generateDeserializerErrorTest(method, "ke2 nonce is all zeros",
				ke2BadServerNonce,
				opaque.ErrKE2, internal.ErrMissingNonce, internal.ErrSliceIsAllZeros),
			generateDeserializerErrorTest(method, "ke2 mac is all zeros",
				ke2BadServerMac,
				opaque.ErrKE2, internal.ErrMissingMAC, internal.ErrSliceIsAllZeros),
		}
		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t2 *testing.T) {
				f := getDeserializerMethod(te.method)

				expectErrors(t, func() error {
					return f(d, te.input)
				}, te.errors...)
			})
		}
	})
}

// TestDeserializer_KE3_Errors verifies that final client messages are validated before server processing, preventing acceptance of truncated MACs or missing key shares.
func TestDeserializer_KE3_Errors(t *testing.T) {
	method := "KE3"
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		d := getDeserializer(t, c)

		tests := []deserializerErrorTest{
			generateDeserializerErrorTestNilInput(method),
			generateDeserializerErrorTestEmptyInput(method),
			generateDeserializerErrorTestInputTooShort(method),
			generateDeserializerErrorTestInputTooLong(method),
			generateDeserializerErrorTest(method, "client mac is all zeros",
				make([]byte, c.MAC.Size()),
				opaque.ErrKE3, internal.ErrInvalidClientMac, internal.ErrSliceIsAllZeros),
		}

		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t2 *testing.T) {
				f := getDeserializerMethod(te.method)

				expectErrors(t, func() error {
					return f(d, te.input)
				}, te.errors...)
			})
		}
	})
}

// TestDeserializeElementScenarios covers element decoding across groups and error cases, which is important for handling externally provided public keys.
func TestDeserializeElementScenarios(t *testing.T) {
	group := ecc.Ristretto255Sha512
	scalar := group.NewScalar().Random()
	valid := group.Base().Multiply(scalar).Encode()

	if _, err := opaque.DeserializeElement(group, valid); err != nil {
		t.Fatalf("unexpected error decoding valid element: %v", err)
	}

	short := valid[:len(valid)-1]
	if _, err := opaque.DeserializeElement(group, short); !errors.Is(err, internal.ErrInvalidEncodingLength) {
		t.Fatalf("expected encoding length error, got %v", err)
	}

	bad := getBadRistrettoElement()
	if _, err := opaque.DeserializeElement(group, bad); !errors.Is(err, internal.ErrInvalidElement) {
		t.Fatalf("expected invalid element error, got %v", err)
	}
}

// TestDeserializeScalarScenarios exercises scalar decoding, making sure invalid encodings are surfaced with precise errors.
func TestDeserializeScalarScenarios(t *testing.T) {
	group := ecc.Ristretto255Sha512
	valid := group.NewScalar().Random().Encode()

	if _, err := opaque.DeserializeScalar(group, valid); err != nil {
		t.Fatalf("unexpected error decoding valid scalar: %v", err)
	}

	short := valid[:len(valid)-1]
	if _, err := opaque.DeserializeScalar(group, short); !errors.Is(err, internal.ErrInvalidEncodingLength) {
		t.Fatalf("expected invalid length error, got %v", err)
	}

	zero := group.NewScalar()
	if _, err := opaque.DeserializeScalar(group, zero.Encode()); !errors.Is(err, internal.ErrScalarZero) {
		t.Fatalf("expected scalar zero error, got %v", err)
	}

	bad := getBadRistrettoScalar()
	if _, err := opaque.DeserializeScalar(group, bad); !errors.Is(err, internal.ErrInvalidScalar) {
		t.Fatalf("expected invalid scalar error, got %v", err)
	}
}

/*
	Decode Keys
*/

// TestDecodeAkePrivateKey demonstrates that valid private keys survive the dedicated decoder, ensuring serialized material can reboot servers.
func TestDecodeAkePrivateKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		key := conf.conf.AKE.Group().NewScalar().Random()

		d := getDeserializer(t, conf.conf)

		if _, err := d.DecodePrivateKey(key.Encode()); err != nil {
			t.Fatalf("unexpected error on valid private key. Group %v, key %v",
				conf.conf.AKE,
				key.Hex(),
			)
		}
	})
}

// TestDecodeBadAkePrivateKey ensures the decoder spots corrupted AKE private keys, a critical guard against tampering.
func TestDecodeBadAkePrivateKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		badKey := conf.getBadScalar()
		d := getDeserializer(t, conf.conf)

		expectErrors(t, func() error {
			_, err := d.DecodePrivateKey(badKey)
			return err
		}, internal.ErrInvalidPrivateKey)
	})
}

// TestDecodeAkePublicKey verifies successful decoding for well-formed public keys, proving the API works for backups and migrations.
func TestDecodeAkePublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		s := conf.conf.AKE.Group().NewScalar().Random()
		p := conf.conf.AKE.Group().Base().Multiply(s)

		d := getDeserializer(t, conf.conf)

		if _, err := d.DecodePublicKey(p.Encode()); err != nil {
			t.Fatalf("unexpected error on valid public key. Group %v, element %v",
				conf.conf.AKE,
				p.Hex(),
			)
		}
	})
}

// TestDecodeBadAkePublicKey ensures invalid public key encodings trigger errors, defending against inconsistent curve points.
func TestDecodeBadAkePublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		badKey := conf.getBadElement()

		d := getDeserializer(t, conf.conf)

		expectErrors(t, func() error {
			_, err := d.DecodePublicKey(badKey)
			return err
		}, internal.ErrInvalidPublicKey)
	})
}
