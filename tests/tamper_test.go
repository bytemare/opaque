// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

// Tampering and attack simulation tests
//
// Covered attacks:
// - Context mismatch between client and server (session binding via transcript context)
// - Identity binding mismatch (ClientIdentity / ServerIdentity variations)
// - Replay/mismatch of transcript messages (KE1/KE2/KE3) and state re-use attempts
// - Unknown key-share style identity substitution (server identity mismatch)
//
// Missing/Deferred:
// - Full replay protections beyond transcript MAC checks (application-level session tracking)
// - Network-level reordering/delay effects
// - Side-channel simulations (timing/cache) — not applicable at unit-test level

import (
	"testing"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

func TestTamper_ContextMismatch(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		// Client uses base configuration
		client := getClient(t2, conf)

		// Server uses same parameters but different Context
		srvConf := *conf.conf
		srvConf.Context = []byte("server-context")
		server, err := srvConf.Server()
		if err != nil {
			t2.Fatal(err)
		}

		// Prepare SKM from original configuration to keep same keys/group
		sk, pk := conf.conf.KeyGen()
		skm := &opaque.ServerKeyMaterial{
			Identity:       nil,
			PrivateKey:     sk,
			PublicKeyBytes: pk.Encode(),
			OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
		}
		if err := server.SetKeyMaterial(skm); err != nil {
			t2.Fatal(err)
		}

		// Registration (context not used in transcript for registration response)
		r1, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatal(err)
		}
		r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
		if err != nil {
			t2.Fatal(err)
		}
		rec, _, err := client.RegistrationFinalize(r2, nil, nil)
		if err != nil {
			t2.Fatal(err)
		}
		record := &opaque.ClientRecord{RegistrationRecord: rec, CredentialIdentifier: credentialIdentifier}

		client.ClearState()
		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t2.Fatal(err)
		}

		expectErrors(t2, func() error {
			_, _, _, err := client.GenerateKE3(ke2, nil, nil)
			return err
		}, opaque.ErrAuthentication)
	})
}

func TestTamper_IdentityBindingMismatch(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
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

		// Supply explicit identities that differ from server's implicit ones
		badClientID := []byte("bad-client-id")
		badServerID := []byte("bad-server-id")

		// ClientIdentity mismatch
		expectErrors(t2, func() error {
			_, _, _, err := client.GenerateKE3(ke2, badClientID, nil)
			return err
		}, opaque.ErrAuthentication)

		// ServerIdentity mismatch
		expectErrors(t2, func() error {
			_, _, _, err := client.GenerateKE3(ke2, nil, badServerID)
			return err
		}, opaque.ErrAuthentication)

		// Both identities mismatch
		expectErrors(t2, func() error {
			_, _, _, err := client.GenerateKE3(ke2, badClientID, badServerID)
			return err
		}, opaque.ErrAuthentication)
	})
}

func TestTamper_KE2MismatchWithClientState(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		rec := registration(t2, client, server, password, credentialIdentifier, nil, serverIdentity)
		client.ClearState()

		// Build two different KE1 messages with two clients
		ke1a, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2a, _, err := server.GenerateKE2(ke1a, rec)
		if err != nil {
			t2.Fatal(err)
		}

		client2 := getClient(t2, conf)
		ke1b, err := client2.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2b, _, err := server.GenerateKE2(ke1b, rec)
		if err != nil {
			t2.Fatal(err)
		}

		// Use KE2b against client1 state (which holds KE1a) → should fail transcript MAC
		expectErrors(
			t2,
			func() error { _, _, _, err := client.GenerateKE3(ke2b, nil, serverIdentity); return err },
			opaque.ErrAuthentication,
		)

		// Complete with ke2a then try to reuse ke3 against a different server output
		ke3, _, _, err := client.GenerateKE3(ke2a, nil, serverIdentity)
		if err != nil {
			t2.Fatal(err)
		}
		// Produce new server output to mismatch
		client.ClearState()
		ke1c, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatal(err)
		}
		ke2c, outC, err := server.GenerateKE2(ke1c, rec)
		if err != nil {
			t2.Fatal(err)
		}
		// Now verify with mismatched output
		expectErrors(t2, func() error { return server.LoginFinish(ke3, outC.ClientMAC) }, opaque.ErrAuthentication)

		// Ensure ke2c can still be used legitimately
		_, _, _, err = client.GenerateKE3(ke2c, nil, serverIdentity)
		if err != nil {
			t2.Fatal(err)
		}
	})
}

func TestTamper_MaskingNonceBitflip(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
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

		// Flip a bit in masking nonce (not all zeros) to break unmasking
		ke2.MaskingNonce[0] ^= 0x01

		// Expect authentication failure due to server public key decode or subsequent MACs
		expectErrors(
			t2,
			func() error { _, _, _, err := client.GenerateKE3(ke2, nil, nil); return err },
			opaque.ErrAuthentication,
		)
	})
}

func TestTamper_MaskedResponseBitflip(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
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

		// Flip a bit in masked response to corrupt decrypted data
		ke2.MaskedResponse[0] ^= 0x80

		expectErrors(
			t2,
			func() error { _, _, _, err := client.GenerateKE3(ke2, nil, nil); return err },
			opaque.ErrAuthentication,
		)
	})
}

// Note: KE3 replay is accepted at the protocol layer because the MAC verifies. Preventing replays
// is the responsibility of the application layer (session tracking). This test documents that behavior.
func TestTamper_KE3Replay_AcceptedWithoutAppTracking(t *testing.T) {
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

		if err := server.LoginFinish(ke3, out.ClientMAC); err != nil {
			t2.Fatalf("unexpected error on first verification: %v", err)
		}
		// Replay the exact same KE3 and MAC
		if err := server.LoginFinish(ke3, out.ClientMAC); err != nil {
			t2.Fatalf("unexpected error on second verification: %v", err)
		}
	})
}
