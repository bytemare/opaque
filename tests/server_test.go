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
	"github.com/bytemare/opaque/message"

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

// T17.1 — NewServer without configuration uses defaults.
func TestNewServer_DefaultConfiguration(t *testing.T) {
	server, err := opaque.NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}

	// Set key material using default configuration
	def := opaque.DefaultConfiguration()
	sk, pk := def.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil,
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: def.GenerateOPRFSeed(),
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		t.Fatal(err)
	}

	client, err := def.Client()
	if err != nil {
		t.Fatal(err)
	}

	// Minimal registration to produce a record
	r1, err := client.RegistrationInit(password)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := client.RegistrationFinalize(r2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	record := &opaque.ClientRecord{RegistrationRecord: rec, CredentialIdentifier: credentialIdentifier}

	client.ClearState()
	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}
	ke2, _, err := server.GenerateKE2(ke1, record)
	if err != nil {
		t.Fatal(err)
	}

	if want, got := def.AKE.Group(), ke2.ServerKeyShare.Group(); want != got {
		t.Fatalf("expected default server group %v, got %v", want, got)
	}
}

// T17.2 — RegistrationResponse with invalid server public key bytes (length).
func TestServer_RegistrationResponse_InvalidServerPublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server := getServer(t2, conf)

		// Valid SKM first, then corrupt the public key bytes length.
		sk, pk := conf.conf.KeyGen()
		if err := server.SetKeyMaterial(&opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: pk.Encode(),
			OPRFGlobalSeed: conf.conf.GenerateOPRFSeed(),
		}); err != nil {
			t2.Fatal(err)
		}
		// Corrupt length
		server.ServerKeyMaterial.PublicKeyBytes = internal.RandomBytes(conf.internal.Group.ElementLength() - 1)

		client := getClient(t2, conf)
		r1, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}

		expectErrors(t2, func() error {
			_, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
			return err
		}, opaque.ErrServerKeyMaterial, internal.ErrInvalidServerPublicKey, internal.ErrInvalidElement, internal.ErrInvalidEncodingLength)
	})
}

// T17.3 — RegistrationResponse with invalid registration request.
func TestServer_RegistrationResponse_InvalidRequest(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server := getServer(t2, conf)
		// Set valid SKM
		sk, pk := conf.conf.KeyGen()
		if err := server.SetKeyMaterial(&opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: pk.Encode(),
			OPRFGlobalSeed: conf.conf.GenerateOPRFSeed(),
		}); err != nil {
			t2.Fatal(err)
		}

		// a) nil request
		expectErrors(t2, func() error {
			_, err := server.RegistrationResponse(nil, credentialIdentifier, nil)
			return err
		}, opaque.ErrRegistration, internal.ErrRegistrationRequestNil)

		// b) blinded message wrong group
		og := getOtherGroup(conf)
		wrong := og.Base().Multiply(og.NewScalar().Random())
		expectErrors(t2, func() error {
			_, err := server.RegistrationResponse(
				&message.RegistrationRequest{BlindedMessage: wrong},
				credentialIdentifier,
				nil,
			)
			return err
		}, opaque.ErrRegistration, internal.ErrInvalidBlindedMessage, internal.ErrElementGroupMismatch)

		// c) blinded message is identity
		g := conf.internal.OPRF.Group()
		zero := g.NewScalar()
		zero.Zero()
		idElem := g.Base().Multiply(zero)
		expectErrors(t2, func() error {
			_, err := server.RegistrationResponse(
				&message.RegistrationRequest{BlindedMessage: idElem},
				credentialIdentifier,
				nil,
			)
			return err
		}, opaque.ErrRegistration, internal.ErrInvalidBlindedMessage, internal.ErrElementIdentity)
	})
}

// T17.4 — GenerateKE2 with invalid KE1, covering sub-cases.
func TestServer_GenerateKE2_InvalidKE1(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		rec := registration(t2, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		// a) nil KE1
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(nil, rec)
			return err
		}, opaque.ErrKE1, internal.ErrKE1Nil)

		// Build a good KE1 as baseline
		goodKE1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}

		// b) invalid blinded message group
		og := getOtherGroup(conf)
		bad := *goodKE1
		bad.BlindedMessage = og.Base().Multiply(og.NewScalar().Random())
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(&bad, rec)
			return err
		}, opaque.ErrKE1, internal.ErrInvalidBlindedMessage, internal.ErrElementGroupMismatch)

		// c) invalid client key share group
		bad2 := *goodKE1
		bad2.ClientKeyShare = og.Base().Multiply(og.NewScalar().Random())
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(&bad2, rec)
			return err
		}, opaque.ErrKE1, internal.ErrInvalidClientKeyShare, internal.ErrElementGroupMismatch)

		// d) missing client nonce
		bad3 := *goodKE1
		bad3.ClientNonce = nil
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(&bad3, rec)
			return err
		}, opaque.ErrKE1, internal.ErrMissingNonce)
	})
}

// T17.5 — GenerateKE2 with invalid options (ClientOPRFKey, MaskingNonce, AKE secret key share).
func TestServer_GenerateKE2_InvalidOptions(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		rec := registration(t2, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}

		// a) ClientOPRFKey wrong group
		og := getOtherGroup(conf)
		badOPRF := og.NewScalar().Random()
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(ke1, rec, &opaque.ServerOptions{ClientOPRFKey: badOPRF})
			return err
		}, opaque.ErrServerOptions, internal.ErrClientOPRFKey)

		// b) MaskingNonce wrong length
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(
				ke1,
				rec,
				&opaque.ServerOptions{MaskingNonce: internal.RandomBytes(conf.internal.NonceLen - 1)},
			)
			return err
		}, opaque.ErrServerOptions, internal.ErrMaskingNonceLength)

		// c) AKE SecretKeyShare wrong group
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(
				ke1,
				rec,
				&opaque.ServerOptions{AKE: &opaque.AKEOptions{SecretKeyShare: og.NewScalar().Random()}},
			)
			return err
		}, opaque.ErrServerOptions, internal.ErrSecretShareInvalid)
	})
}

// T17.6 — GenerateKE2 with invalid client record (cover sub-cases).
func TestServer_GenerateKE2_InvalidRecord(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		_, server := setup(t2, conf)
		// a) nil record
		ke1 := func() *message.KE1 {
			c := getClient(t2, conf)
			k, err := c.GenerateKE1(password)
			if err != nil {
				t2.Fatal(err)
			}
			return k
		}()
		expectErrors(t2, func() error {
			_, _, err := server.GenerateKE2(ke1, nil)
			return err
		}, opaque.ErrClientRecord, internal.ErrClientRecordNil)

		// Build valid record
		client, server2 := setup(t2, conf)
		rec := registration(t2, client, server2, password, credentialIdentifier, nil, nil)
		client.ClearState()
		goodKE1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}

		// b) missing registration record
		badRec := &opaque.ClientRecord{
			CredentialIdentifier: rec.CredentialIdentifier,
			ClientIdentity:       rec.ClientIdentity,
			RegistrationRecord:   nil,
		}
		expectErrors(t2, func() error {
			_, _, err := server2.GenerateKE2(goodKE1, badRec)
			return err
		}, opaque.ErrClientRecord, internal.ErrNilRegistrationRecord)

		// c) invalid client public key (wrong group)
		og := getOtherGroup(conf)
		e := og.Base().Multiply(og.NewScalar().Random())
		rec2 := *rec.RegistrationRecord
		rec2.ClientPublicKey = e
		badRec2 := &opaque.ClientRecord{
			CredentialIdentifier: rec.CredentialIdentifier,
			ClientIdentity:       rec.ClientIdentity,
			RegistrationRecord:   &rec2,
		}
		expectErrors(t2, func() error {
			_, _, err := server2.GenerateKE2(goodKE1, badRec2)
			return err
		}, opaque.ErrClientRecord, internal.ErrInvalidClientPublicKey, internal.ErrElementGroupMismatch)

		// d) envelope invalid length handled by existing test (TestServerInit_InvalidEnvelope)

		// e) masking key invalid length
		rec3 := *rec.RegistrationRecord
		rec3.MaskingKey = internal.RandomBytes(conf.internal.KDF.Size() - 1)
		badRec3 := &opaque.ClientRecord{
			CredentialIdentifier: rec.CredentialIdentifier,
			ClientIdentity:       rec.ClientIdentity,
			RegistrationRecord:   &rec3,
		}
		expectErrors(t2, func() error {
			_, _, err := server2.GenerateKE2(goodKE1, badRec3)
			return err
		}, opaque.ErrClientRecord, internal.ErrEnvelopeInvalid, internal.ErrInvalidMaskingKey)

		// f) masking key all zeros
		rec4 := *rec.RegistrationRecord
		rec4.MaskingKey = make([]byte, conf.internal.KDF.Size())
		badRec4 := &opaque.ClientRecord{
			CredentialIdentifier: rec.CredentialIdentifier,
			ClientIdentity:       rec.ClientIdentity,
			RegistrationRecord:   &rec4,
		}
		expectErrors(t2, func() error {
			_, _, err := server2.GenerateKE2(goodKE1, badRec4)
			return err
		}, opaque.ErrClientRecord, internal.ErrInvalidMaskingKey, internal.ErrSliceIsAllZeros)

		// g) missing credential identifier
		badRec5 := &opaque.ClientRecord{
			CredentialIdentifier: nil,
			ClientIdentity:       rec.ClientIdentity,
			RegistrationRecord:   rec.RegistrationRecord,
		}
		expectErrors(t2, func() error {
			_, _, err := server2.GenerateKE2(goodKE1, badRec5)
			return err
		}, internal.ErrNoCredentialIdentifier)
	})
}

// T17.7 — LoginFinish with nil ke3 and invalid MAC.
func TestServer_LoginFinish_InvalidInputs(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		rec := registration(t2, client, server, password, credentialIdentifier, nil, nil)
		client.ClearState()
		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2, out, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t2.Fatal(err)
		}
		ke3, _, _, err := client.GenerateKE3(ke2, nil, nil)
		if err != nil {
			t2.Fatal(err)
		}

		// a) nil ke3
		expectErrors(t2, func() error {
			return server.LoginFinish(nil, out.ClientMAC)
		}, opaque.ErrKE3, internal.ErrKE3Nil)

		// b) invalid mac
		bad := *ke3
		bad.ClientMac = append([]byte(nil), ke3.ClientMac...)
		bad.ClientMac[0] ^= 0xff
		expectErrors(t2, func() error {
			return server.LoginFinish(&bad, out.ClientMAC)
		}, opaque.ErrAuthentication, internal.ErrClientAuthentication, internal.ErrInvalidClientMac)
	})
}

// T17.8 — SetKeyMaterial with invalid inputs, and GenerateKE2 path with invalid SKM.
func TestServer_SetKeyMaterial_Invalid(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server := getServer(t2, conf)

		// a) invalid private key group
		og := getOtherGroup(conf)
		badSk := og.NewScalar().Random()
		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     badSk,
			PublicKeyBytes: conf.getValidElementBytes(),
			OPRFGlobalSeed: conf.conf.GenerateOPRFSeed(),
		}
		expectErrors(
			t2,
			func() error { return server.SetKeyMaterial(skm) },
			opaque.ErrServerKeyMaterial,
			internal.ErrInvalidPrivateKey,
		)

		// b) invalid public key bytes (decode failure)
		sk, _ := conf.conf.KeyGen()
		skm = &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: conf.getBadElement(),
			OPRFGlobalSeed: conf.conf.GenerateOPRFSeed(),
		}
		expectErrors(
			t2,
			func() error { return server.SetKeyMaterial(skm) },
			opaque.ErrServerKeyMaterial,
			internal.ErrInvalidPublicKey,
		)

		// c) public key mismatch
		sk1, _ := conf.conf.KeyGen()
		_, pk2 := conf.conf.KeyGen()
		skm = &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk1,
			PublicKeyBytes: pk2.Encode(),
			OPRFGlobalSeed: conf.conf.GenerateOPRFSeed(),
		}
		expectErrors(
			t2,
			func() error { return server.SetKeyMaterial(skm) },
			opaque.ErrServerKeyMaterial,
			internal.ErrInvalidPublicKeyBytes,
		)
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
//		verify that calling SetKeyMaterial with a nil secret key produces an error
//	whose message begins with the expected prefix. The core assertion was that providing nil secret material
//	must never succeed and must return a descriptive error.
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
//      verify that a zero-valued secret key is rejected. Depending on the group
//	selected, the error either indicates a zero private key or an invalid scalar decoding. These tests are
//	commented out because their conditions are now covered by more granular unit tests elsewhere or were
//	superseded by fuzzing and input validation logic.
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
