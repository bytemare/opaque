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
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

// TestIdentityFallbackProtocol verifies that nil client/server identities fall back to the corresponding public keys
// in the registration and login flows, including mixed cases where only one identity is omitted.
func TestIdentityFallbackProtocol(t *testing.T) {
	type identityCase struct {
		name              string
		clientIdentity    []byte
		serverIdentity    []byte
		serverSKMIdentity []byte
	}

	cases := []identityCase{
		{
			name:              "both-nil",
			clientIdentity:    nil,
			serverIdentity:    nil,
			serverSKMIdentity: nil,
		},
		{
			name:              "client-nil",
			clientIdentity:    nil,
			serverIdentity:    serverIdentity,
			serverSKMIdentity: serverIdentity,
		},
		{
			name:              "server-nil",
			clientIdentity:    clientIdentity,
			serverIdentity:    nil,
			serverSKMIdentity: nil,
		},
	}

	testAll(t, func(t2 *testing.T, conf *configuration) {
		for _, tc := range cases {
			t2.Run(tc.name, func(t3 *testing.T) {
				server := getServer(t3, conf)
				sk, pk := conf.conf.KeyGen()
				if err := server.SetKeyMaterial(&opaque.ServerKeyMaterial{
					Identity:       tc.serverSKMIdentity,
					PrivateKey:     sk,
					PublicKeyBytes: pk.Encode(),
					OPRFGlobalSeed: conf.conf.GenerateOPRFSeed(),
				}); err != nil {
					t3.Fatalf("failed to set server key material: %v", err)
				}

				client := getClient(t3, conf)
				regBlind := conf.conf.OPRF.Group().NewScalar().Random()
				regNonce := internal.RandomBytes(conf.internal.NonceLen)

				req, err := client.RegistrationInit(password, &opaque.ClientOptions{OPRFBlind: regBlind})
				if err != nil {
					t3.Fatalf("registration init failed: %v", err)
				}

				resp, err := server.RegistrationResponse(req, credentialIdentifier, nil)
				if err != nil {
					t3.Fatalf("registration response failed: %v", err)
				}

				recordBase, exportBase, err := client.RegistrationFinalize(
					resp,
					tc.clientIdentity,
					tc.serverIdentity,
					&opaque.ClientOptions{EnvelopeNonce: regNonce},
				)
				if err != nil {
					t3.Fatalf("registration finalize failed: %v", err)
				}

				explicitClientID := tc.clientIdentity
				if explicitClientID == nil {
					explicitClientID = recordBase.ClientPublicKey.Encode()
				}
				explicitServerID := tc.serverIdentity
				if explicitServerID == nil {
					explicitServerID = server.ServerKeyMaterial.PublicKeyBytes
				}

				recordExplicit, exportExplicit, err := client.RegistrationFinalize(
					resp,
					explicitClientID,
					explicitServerID,
					&opaque.ClientOptions{EnvelopeNonce: regNonce},
				)
				if err != nil {
					t3.Fatalf("explicit registration finalize failed: %v", err)
				}

				if !bytes.Equal(recordBase.Serialize(), recordExplicit.Serialize()) {
					t3.Fatal("registration record mismatch between implicit and explicit identities")
				}
				if !bytes.Equal(exportBase, exportExplicit) {
					t3.Fatal("registration export key mismatch between implicit and explicit identities")
				}

				record := &opaque.ClientRecord{
					CredentialIdentifier: credentialIdentifier,
					ClientIdentity:       tc.clientIdentity,
					RegistrationRecord:   recordBase,
				}

				ke1Blind := conf.conf.OPRF.Group().NewScalar().Random()
				clientSecretShare := conf.conf.AKE.Group().NewScalar().Random()
				clientNonce := internal.RandomBytes(conf.internal.NonceLen)
				clientOptions := &opaque.ClientOptions{
					OPRFBlind: ke1Blind,
					AKE: &opaque.AKEOptions{
						SecretKeyShare: clientSecretShare,
						Nonce:          clientNonce,
					},
				}

				clientNil := getClient(t3, conf)
				ke1, err := clientNil.GenerateKE1(password, clientOptions)
				if err != nil {
					t3.Fatalf("generate KE1 failed: %v", err)
				}

				serverSecretShare := conf.conf.AKE.Group().NewScalar().Random()
				serverNonce := internal.RandomBytes(conf.internal.NonceLen)
				maskingNonce := internal.RandomBytes(conf.internal.NonceLen)
				ke2, serverOut, err := server.GenerateKE2(
					ke1,
					record,
					&opaque.ServerOptions{
						MaskingNonce: maskingNonce,
						AKE: &opaque.AKEOptions{
							SecretKeyShare: serverSecretShare,
							Nonce:          serverNonce,
						},
					},
				)
				if err != nil {
					t3.Fatalf("generate KE2 failed: %v", err)
				}

				ke3Nil, sessionNil, exportNil, err := clientNil.GenerateKE3(
					ke2,
					tc.clientIdentity,
					tc.serverIdentity,
				)
				if err != nil {
					t3.Fatalf("generate KE3 with nil identities failed: %v", err)
				}

				clientExplicit := getClient(t3, conf)
				if _, err := clientExplicit.GenerateKE1(password, clientOptions); err != nil {
					t3.Fatalf("generate explicit KE1 failed: %v", err)
				}

				ke3Explicit, sessionExplicit, exportExplicit, err := clientExplicit.GenerateKE3(
					ke2,
					explicitClientID,
					explicitServerID,
				)
				if err != nil {
					t3.Fatalf("generate KE3 with explicit identities failed: %v", err)
				}

				if !bytes.Equal(ke3Nil.Serialize(), ke3Explicit.Serialize()) {
					t3.Fatal("KE3 mismatch between implicit and explicit identities")
				}
				if !bytes.Equal(sessionNil, sessionExplicit) {
					t3.Fatal("session key mismatch between implicit and explicit identities")
				}
				if !bytes.Equal(exportNil, exportExplicit) {
					t3.Fatal("export key mismatch between implicit and explicit identities")
				}

				if err := server.LoginFinish(ke3Nil, serverOut.ClientMAC); err != nil {
					t3.Fatalf("server rejected implicit KE3: %v", err)
				}
				if err := server.LoginFinish(ke3Explicit, serverOut.ClientMAC); err != nil {
					t3.Fatalf("server rejected explicit KE3: %v", err)
				}
			})
		}
	})
}
