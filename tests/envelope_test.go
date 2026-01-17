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

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/envelope"
)

func assertEnvelopeRecover(
	t *testing.T,
	conf *internal.Configuration,
	randomizedPassword, serverPublicKey, clientIdentity, serverIdentity []byte,
	env *envelope.Envelope,
	expectedClientPublicKey []byte,
) {
	t.Helper()

	_, clientPublicKey, _, err := envelope.Recover(
		conf,
		randomizedPassword,
		serverPublicKey,
		clientIdentity,
		serverIdentity,
		env,
	)
	if err != nil {
		t.Fatalf("unexpected envelope recover error: %v", err)
	}

	if !bytes.Equal(clientPublicKey.Encode(), expectedClientPublicKey) {
		t.Fatalf("unexpected client public key from envelope recovery")
	}
}

// TestEnvelopeIdentityFallback verifies that nil client/server identities fall back to the corresponding public keys.
func TestEnvelopeIdentityFallback(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		internalConf := conf.internal
		randomizedPassword := internal.RandomBytes(internalConf.KDF.Size())
		nonce := internal.RandomBytes(internalConf.NonceLen)

		_, serverPublicKey := conf.conf.KeyGen()
		serverPublicKeyBytes := serverPublicKey.Encode()

		// Both identities nil should use public keys.
		envNil, pkuNil, _ := envelope.Store(
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			nil,
			nil,
			nonce,
		)
		assertEnvelopeRecover(
			t2,
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			pkuNil.Encode(),
			serverPublicKeyBytes,
			envNil,
			pkuNil.Encode(),
		)

		// Explicit identities equal to public keys should recover even if caller passes nil.
		envExplicit, pkuExplicit, _ := envelope.Store(
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			pkuNil.Encode(),
			serverPublicKeyBytes,
			nonce,
		)
		if !pkuExplicit.Equal(pkuNil) {
			t2.Fatal("expected deterministic client public key for the same inputs")
		}
		assertEnvelopeRecover(
			t2,
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			nil,
			nil,
			envExplicit,
			pkuExplicit.Encode(),
		)

		// Only client identity nil should fall back to the derived client public key.
		envClientNil, pkuClientNil, _ := envelope.Store(
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			nil,
			serverIdentity,
			nonce,
		)
		assertEnvelopeRecover(
			t2,
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			pkuClientNil.Encode(),
			serverIdentity,
			envClientNil,
			pkuClientNil.Encode(),
		)

		// Only server identity nil should fall back to the server public key.
		envServerNil, pkuServerNil, _ := envelope.Store(
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			clientIdentity,
			nil,
			nonce,
		)
		assertEnvelopeRecover(
			t2,
			internalConf,
			randomizedPassword,
			serverPublicKeyBytes,
			clientIdentity,
			serverPublicKeyBytes,
			envServerNil,
			pkuServerNil.Encode(),
		)
	})
}
