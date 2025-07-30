// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ake

import (
	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

// Start initiates the 3DH protocol, and returns a KE1 message with clientInfo.
func Start(g ecc.Group, options *Options) (*message.KE1, *ecc.Scalar) {
	esk, epk := options.GetEphemeralKeyShare(g)

	return &message.KE1{
		CredentialRequest:    nil,
		ClientNonce:          options.Nonce,
		ClientPublicKeyshare: epk,
	}, esk
}

// Finalize verifies and responds to KE3. If the handshake is successful, the session key is stored and this functions
// returns a KE3 message.
func Finalize(
	conf *internal.Configuration,
	clientKM *KeyMaterial,
	identities *Identities,
	serverPublicKey *ecc.Element,
	ke2 *message.KE2,
	ke1 []byte,
) (*message.KE3, []byte, bool) {
	ikm := k3dh(
		ke2.ServerPublicKeyshare,
		clientKM.EphemeralSecretKey,
		serverPublicKey,
		clientKM.EphemeralSecretKey,
		ke2.ServerPublicKeyshare,
		clientKM.SecretKey,
	)
	sessionSecret, serverMac, clientMac := core3DH(conf, identities, ikm, ke1, ke2)

	if !conf.MAC.Equal(serverMac, ke2.ServerMac) {
		return nil, nil, false
	}

	return &message.KE3{ClientMac: clientMac}, sessionSecret, true
}
