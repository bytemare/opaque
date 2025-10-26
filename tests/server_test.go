// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
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
			expected []error
			name     string
			seed     []byte
		}{
			{
				name:     "nil seed",
				seed:     nil,
				expected: []error{opaque.ErrServerKeyMaterial, internal.ErrOPRFKeyNoSeed},
			},
			{
				name:     "short seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() - 1),
				expected: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidOPRFSeedLength},
			},
			{
				name:     "long seed",
				seed:     internal.RandomBytes(conf.conf.Hash.Size() + 1),
				expected: []error{opaque.ErrServerKeyMaterial, internal.ErrInvalidOPRFSeedLength},
			},
		}

		for _, tt := range seeds {
			t.Run(tt.name, func(t2 *testing.T) {
				server.ServerKeyMaterial.OPRFGlobalSeed = tt.seed

				expectErrors(t, func() error {
					_, err = server.RegistrationResponse(nil, credentialIdentifier, nil)
					return err
				}, tt.expected...)

				ke1, err := client.GenerateKE1(password)
				if err != nil {
					t.Fatalf("unexpected error %s", err)
				}

				client.ClearState()

				expectErrors(t, func() error {
					_, _, err := server.GenerateKE2(ke1, fakeRecord)
					return err
				}, tt.expected...)
			})
		}
	})
}

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

func TestServer_RegistrationResponse_ExplicitOPRFKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)

		req, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}

		explicit := conf.internal.OPRF.Group().NewScalar().Random()
		resp, err := server.RegistrationResponse(req, credentialIdentifier, explicit)
		if err != nil {
			t2.Fatalf("expected explicit OPRF key to work, got %v", err)
		}
		if resp == nil || resp.EvaluatedMessage == nil {
			t2.Fatal("expected evaluated message in registration response")
		}
	})
}

func TestServer_RegistrationResponse_ExplicitOPRFKeyErrors(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)

		req, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}

		bad := getOtherGroup(conf).NewScalar().Random()
		expectErrors(t2, func() error {
			_, err := server.RegistrationResponse(req, credentialIdentifier, bad)
			return err
		}, opaque.ErrServerOptions, internal.ErrClientOPRFKey)

		expectErrors(t2, func() error {
			_, err := server.RegistrationResponse(req, nil, nil)
			return err
		}, internal.ErrNoCredentialIdentifier)
	})
}

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

func TestServer_LoginFinish_InvalidInputs(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		rec := registration(t2, client, server, password, credentialIdentifier, nil, serverIdentity)
		client.ClearState()

		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}

		ke2, out, err := server.GenerateKE2(ke1, rec)
		if err != nil {
			t2.Fatal(err)
		}

		ke3, _, _, err := client.GenerateKE3(ke2, nil, serverIdentity)
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

	record := registration(t, client, server, password, credentialIdentifier, nil, serverIdentity)
	client.ClearState()

	ke1, err := client.GenerateKE1(password)
	if err != nil {
		t.Fatal(err)
	}

	ke2, serverOutput, err := server.GenerateKE2(ke1, record)
	if err != nil {
		t.Fatal(err)
	}

	ke3, _, _, err := client.GenerateKE3(ke2, nil, serverIdentity)
	if err != nil {
		t.Fatal(err)
	}

	ke3.ClientMac[0] = ^ke3.ClientMac[0]

	expectErrors(t, func() error {
		err = server.LoginFinish(ke3, serverOutput.ClientMAC)
		return err
	}, opaque.ErrAuthentication, internal.ErrClientAuthentication)
}
