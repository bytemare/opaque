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
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"

	group "github.com/bytemare/ecc"
)

/*
	The following tests look for failing conditions.
*/

func TestServerInit_InvalidOPRFSeedLength(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		sk, pk := conf.conf.KeyGen()

		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: pk.Encode(),
			OPRFGlobalSeed: nil,
		}

		if err = server.SetKeyMaterial(skm); err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		fakeRecord, err := conf.conf.GetFakeRecord(credentialIdentifier)
		if err != nil {
			t.Fatalf("unexpected error %s", err)
		}

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		seeds := []struct {
			expected error
			name     string
			seed     []byte
		}{
			{
				name:     "nil seed",
				seed:     nil,
				expected: internal.ErrOPRFKeyNoSeed,
			},
			{
				name:     "short seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() - 1),
				expected: internal.ErrInvalidOPRFSeedLength,
			},
			{
				name:     "long seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() + 1),
				expected: internal.ErrInvalidOPRFSeedLength,
			},
		}

		for _, tt := range seeds {
			t.Run(tt.name, func(t2 *testing.T) {
				server.ServerKeyMaterial.OPRFGlobalSeed = tt.seed

				expectErrors(t, func() error {
					_, err = server.RegistrationResponse(nil, credentialIdentifier, nil)
					return err
				}, tt.expected)

				ke1, err := client.GenerateKE1(password)
				if err != nil {
					t.Fatalf("unexpected error %s", err)
				}

				client.ClearState()

				expectErrors(t, func() error {
					_, _, err := server.GenerateKE2(ke1, fakeRecord)
					return err
				}, tt.expected)
			})
		}
	})
}

func TestServerKeyMaterial_Decode_Success(t *testing.T) {
	// encode -> decode -> check equality
	testAll(t, func(t2 *testing.T, conf *configuration) {
		sk, pk := conf.conf.KeyGen()
		skm := &opaque.ServerKeyMaterial{
			Identity:       serverIdentity,
			PrivateKey:     sk,
			PublicKeyBytes: pk.Encode(),
			OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
		}

		tests := []struct {
			input *opaque.ServerKeyMaterial
			name  string
			hex   bool
		}{
			{
				name:  "Bytes, Fully populated",
				input: skm,
				hex:   false,
			},
			{
				name: "Bytes, Empty Identity",
				input: &opaque.ServerKeyMaterial{
					Identity:       nil,
					PrivateKey:     skm.PrivateKey,
					PublicKeyBytes: skm.PublicKeyBytes,
					OPRFGlobalSeed: skm.OPRFGlobalSeed,
				},
				hex: false,
			},
			{
				name: "Bytes, Empty OPRFGlobalSeed",
				input: &opaque.ServerKeyMaterial{
					Identity:       skm.Identity,
					PrivateKey:     skm.PrivateKey,
					PublicKeyBytes: skm.PublicKeyBytes,
					OPRFGlobalSeed: nil,
				},
				hex: false,
			},
			{
				name: "Bytes, Empty PrivateKey",
				input: &opaque.ServerKeyMaterial{
					Identity:       skm.Identity,
					PrivateKey:     nil,
					PublicKeyBytes: skm.PublicKeyBytes,
					OPRFGlobalSeed: skm.OPRFGlobalSeed,
				},
				hex: false,
			},
			{
				name:  "Hex, Fully populated",
				input: skm,
				hex:   true,
			},
			{
				name: "Hex, Empty Identity",
				input: &opaque.ServerKeyMaterial{
					Identity:       nil,
					PrivateKey:     skm.PrivateKey,
					PublicKeyBytes: skm.PublicKeyBytes,
					OPRFGlobalSeed: skm.OPRFGlobalSeed,
				},
				hex: true,
			},
			{
				name: "Hex, Empty OPRFGlobalSeed",
				input: &opaque.ServerKeyMaterial{
					Identity:       skm.Identity,
					PrivateKey:     skm.PrivateKey,
					PublicKeyBytes: skm.PublicKeyBytes,
					OPRFGlobalSeed: nil,
				},
				hex: true,
			},
			{
				name: "Hex, Empty PrivateKey",
				input: &opaque.ServerKeyMaterial{
					Identity:       skm.Identity,
					PrivateKey:     nil,
					PublicKeyBytes: skm.PublicKeyBytes,
					OPRFGlobalSeed: skm.OPRFGlobalSeed,
				},
				hex: true,
			},
		}

		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t *testing.T) {
				if te.hex {
					encoded := skm.Hex()
					decoded, err := conf.conf.DecodeServerKeyMaterialHex(encoded)
					if err != nil {
						t.Fatalf("unexpected error %s", err)
					}

					validateServerKeyMaterial(t, decoded, skm)

					reEncoded := decoded.Hex()
					if encoded != reEncoded {
						t.Fatalf(
							"re-encoded ServerKeyMaterial does not match original encoding: \nOriginal: %x\nRe-encoded: %x",
							encoded,
							reEncoded,
						)
					}
				} else {
					encoded := skm.Encode()
					decoded, err := conf.conf.DecodeServerKeyMaterial(encoded)
					if err != nil {
						t.Fatalf("unexpected error %s", err)
					}

					validateServerKeyMaterial(t, decoded, skm)

					reEncoded := decoded.Encode()
					if !bytes.Equal(encoded, reEncoded) {
						t.Fatalf("re-encoded ServerKeyMaterial does not match original encoding: \nOriginal: %x\nRe-encoded: %x", hex.EncodeToString(encoded), hex.EncodeToString(reEncoded))
					}
				}
			})
		}
	})
}

func validateServerKeyMaterial(t *testing.T, decoded, reference *opaque.ServerKeyMaterial) {
	t.Helper()
	switch {
	case decoded == nil:
		t.Fatal("expected non-nil decoded ServerKeyMaterial")
	case decoded.Identity == nil || bytes.Compare(decoded.Identity, reference.Identity) != 0:
		t.Fatalf(
			"decoded ServerKeyMaterial.Identity does not match expected value, want %q, got %q",
			reference.Identity,
			decoded.Identity,
		)
	case decoded.PrivateKey == nil || !decoded.PrivateKey.Equal(reference.PrivateKey):
		t.Fatalf(
			"decoded ServerKeyMaterial.PrivateKey does not match expected value, want %q, got %q",
			decoded.PrivateKey.Hex(),
			reference.PrivateKey.Hex(),
		)
	case decoded.PublicKeyBytes == nil || !bytes.Equal(decoded.PublicKeyBytes, reference.PublicKeyBytes):
		t.Fatalf(
			"decoded ServerKeyMaterial.PublicKeyBytes does not match expected value, want %q, got %q",
			hex.EncodeToString(decoded.PublicKeyBytes),
			hex.EncodeToString(reference.PublicKeyBytes),
		)
	case decoded.OPRFGlobalSeed == nil || !bytes.Equal(decoded.OPRFGlobalSeed, reference.OPRFGlobalSeed):
		t.Fatalf(
			"decoded ServerKeyMaterial.OPRFGlobalSeed does not match expected value, want %q, got %q",
			reference.Identity,
			decoded.Identity,
		)
	default:
		// All checks passed, the decoding was successful.
	}
}

func TestServerKeyMaterial_Decode_Failure(t *testing.T) {
	// todo: add fuzz target
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		g := c.AKE.Group()
		sk, pk := c.KeyGen()
		encodedSkBytes := encoding.EncodeVector(sk.Encode())
		encodedPkBytes := encoding.EncodeVector(pk.Encode())
		encodedSeed := encoding.EncodeVector(internal.RandomBytes(c.Hash.Size()))
		encodedServerIdentity := encoding.EncodeVector(serverIdentity)

		var wrongGroup group.Group
		if g == group.Ristretto255Sha512 {
			wrongGroup = group.P256Sha256
		} else {
			wrongGroup = group.Ristretto255Sha512
		}

		tests := []struct {
			name           string
			input          []byte
			expectedErrors []error
		}{
			{
				name:           "nil input",
				input:          nil,
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidEncodingLength},
			},
			{
				name:           "empty input",
				input:          []byte{},
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidEncodingLength},
			},
			{
				name:           "input too short for header",
				input:          []byte{0, 0, 0, 0, 0, 0, 0, 0},
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidEncodingLength},
			},
			{
				name:           "invalid group id 0",
				input:          []byte{0, 0, 0, 0, 0, 0, 0, 0, 0},
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidGroupEncoding},
			},
			{
				name:           "invalid group id 2",
				input:          []byte{2, 0, 0, 0, 0, 0, 0, 0, 0},
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidGroupEncoding},
			},
			{
				name:           "invalid group id 6",
				input:          []byte{6, 0, 0, 0, 0, 0, 0, 0, 0},
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidGroupEncoding},
			},
			{
				name:           "wrong group for configuration",
				input:          []byte{byte(wrongGroup), 0, 0, 0, 0, 0, 0, 0, 0},
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrWrongGroup},
			},
			{
				name: "invalid encoding: too short",
				input: encoding.Concat(
					[]byte{byte(g)},
					internal.RandomBytes(5+g.ElementLength()-1),
				), // Group byte + 5 bytes for the header, 1 byte too short for the public key
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidEncodingLength},
			},
			{
				name: "invalid encoding: too long", // the length exceeds what's announced on the identity header
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encodedPkBytes,
					encodedSeed,
					[]byte{0, 4}, // server identity header announces a length
					[]byte{
						3,
						3,
						3,
						3,
						3,
						3,
					}, // but server identity exceeds this length, making the total length invalid
				),
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidEncodingLength},
			},
			{
				name: "private key is zero",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encoding.EncodeVector(g.NewScalar().Encode()),
					encodedPkBytes,
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidPrivateKey,
					internal.ErrScalarZero,
				},
			},
			{
				name: "invalid private key encoding (too short)",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encoding.EncodeVector(sk.Encode()[:g.ScalarLength()-2]), // 2 bytes too short
					encodedPkBytes,
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidPrivateKey,
					internal.ErrInvalidScalar,
					internal.ErrInvalidEncodingLength,
				},
			},
			{
				name: "invalid private key encoding (too long)",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encoding.EncodeVector(encoding.Concat(sk.Encode(), []byte{2, 2})), // 2 bytes too long
					encodedPkBytes,
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidPrivateKey,
					internal.ErrInvalidScalar,
				},
			},
			{
				name: "invalid private key (out of range)",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encoding.EncodeVector(conf.getBadScalar()),
					encodedPkBytes,
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidPrivateKey,
					internal.ErrInvalidScalar,
				},
			},
			{
				name: "public key is all zeros",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(make([]byte, g.ElementLength())),
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidServerPublicKey,
					internal.ErrInvalidPublicKeyBytes,
				},
			},
			{
				name: "invalid public key encoding (too short)",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(pk.Encode()[:g.ElementLength()-2]),
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidServerPublicKey,
					internal.ErrInvalidElement,
					internal.ErrInvalidEncodingLength,
				},
			},
			{
				name: "invalid public key encoding (too long)",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(encoding.Concat(pk.Encode(), []byte{2, 2})),
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidServerPublicKey,
					internal.ErrInvalidElement,
					internal.ErrInvalidEncodingLength,
				},
			},
			{
				name: "public key is identity point",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(g.NewElement().Encode()),
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidServerPublicKey,
					internal.ErrInvalidElement,
					internal.ErrInvalidPublicKeyBytes,
				},
			},
			{
				name: "public key is base",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(g.Base().Encode()),
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidServerPublicKey,
					internal.ErrElementIsBase,
				},
			},
			{
				name: "public key is invalid",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(conf.getBadElement()),
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{
					opaque.ErrServerKeyMaterial,
					internal.ErrInvalidServerPublicKey,
					internal.ErrInvalidPublicKeyBytes,
				},
			},
			{
				name: "public key doesn't match secret key",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encoding.EncodeVector(conf.getValidElementBytes()), // very few chances that the random matches
					encodedSeed,
					encodedServerIdentity,
				),
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidServerPublicKey},
			},
			{
				name: "seed is too short",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encodedPkBytes,
					encoding.EncodeVector(internal.RandomBytes(c.Hash.Size()-1)), // 1 byte too short
					encodedServerIdentity,
				),
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidOPRFSeedLength},
			},
			{
				name: "seed is too long",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encodedPkBytes,
					encoding.EncodeVector(internal.RandomBytes(c.Hash.Size()+1)), // 1 byte too long
					encodedServerIdentity,
				),
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidOPRFSeedLength},
			},
			{
				name: "seed header induces invalid length",
				input: encoding.Concatenate(
					[]byte{byte(g)},
					encodedSkBytes,
					encodedPkBytes,
					encoding.Concat(
						encoding.I2OSP(c.Hash.Size(), 2),
						internal.RandomBytes(c.Hash.Size()-len(encodedServerIdentity)-1),
					),
					encodedServerIdentity,
				),
				expectedErrors: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidOPRFSeedLength},
			},
		}

		for _, te := range tests {
			t.Run(fmt.Sprintf("%s-%s", conf.name, te.name), func(t *testing.T) {
				expectErrors(t, func() error {
					_, err := conf.conf.DecodeServerKeyMaterial(te.input)
					return err
				}, te.expectedErrors...)
			})
		}
	})
}

//func TestServerInit_NilSecretKey(t *testing.T) {
//	/*
//		Nil server secret key
//	*/
//	testAll(t, func(t2 *testing.T, conf *configuration) {
//		server, err := conf.conf.Server()
//		if err != nil {
//			t.Fatal(err)
//		}
//		_, pk := conf.conf.KeyGen()
//		expected := "invalid server AKE secret key: "
//
//		if err := server.SetKeyMaterial(nil, nil, pk, nil); err == nil ||
//			!strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("expected error on nil secret key - got %s", err)
//		}
//	})
//}

//func TestServerInit_ZeroSecretKey(t *testing.T) {
//	/*
//		Nil server secret key
//	*/
//	testAll(t, func(t2 *testing.T, conf *configuration) {
//		server, err := conf.conf.Server()
//		if err != nil {
//			t.Fatal(err)
//		}
//		sk := [32]byte{}
//
//		var expected string
//
//		switch conf.conf.AKE.Group() {
//		case group.Ristretto255Sha512, group.P256Sha256:
//			expected = "server private key is zero"
//		default:
//			expected = "invalid server AKE secret key: scalar Decode: invalid scalar length"
//		}
//
//		if err := server.SetKeyMaterial(nil, sk[:], nil, nil); err == nil ||
//			!strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("expected error on nil secret key - got %s", err)
//		}
//	})
//}

func TestServerInit_NoKeyMaterial(t *testing.T) {
	/*
		SetKeyMaterial has not been called or was not successful
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			err = server.SetKeyMaterial(nil)
			return err
		}, internal.ErrServerKeyMaterialNil)

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			_, _, err = server.GenerateKE2(ke1, nil)
			return err
		}, internal.ErrServerKeyMaterialNil)
	})
}

func TestServerInit_InvalidEnvelope(t *testing.T) {
	/*
		Record envelope of invalid length
	*/
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t, conf)
		record := registration(t, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()
		record.Envelope = internal.RandomBytes(15)

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t.Fatal(err)
		}

		expectErrors(t, func() error {
			_, _, err = server.GenerateKE2(ke1, record)
			return err
		}, opaque.ErrClientRecord, internal.ErrEnvelopeInvalid, internal.ErrInvalidEncodingLength)
	})
}

func TestServerFinish_InvalidKE3Mac(t *testing.T) {
	/*
		ke3 mac is invalid
	*/
	conf := configurationTable[0]
	client, server := setup(t, conf)

	record := registration(t, client, server, password, credentialIdentifier, nil, nil)
	client.ClearState()

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}

	ke2, serverOutput, err := server.GenerateKE2(ke1, record)
	if err != nil {
		t.Fatal(err)
	}

	ke3, _, _, err := client.GenerateKE3(ke2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	ke3.ClientMac[0] = ^ke3.ClientMac[0]

	expectErrors(t, func() error {
		err = server.LoginFinish(ke3, serverOutput.ClientMAC)
		return err
	}, opaque.ErrAuthentication, internal.ErrClientAuthentication)
}
