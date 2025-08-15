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

// Respond produces a 3DH server response message.
func Respond(
	conf *internal.Configuration,
	secretKey, ephemeralSecretKey *ecc.Scalar,
	identities *Identities,
	clientPublicKey *ecc.Element,
	ke2 *message.KE2,
	ke1 *message.KE1,
) (clientMac, sessionSecret []byte) {
	ikm := k3dh(
		ke1.ClientKeyShare,
		ephemeralSecretKey,
		ke1.ClientKeyShare,
		secretKey,
		clientPublicKey,
		ephemeralSecretKey,
	)
	sessionSecret, serverMac, clientMac := core3DH(conf, identities, ikm, ke1.Serialize(), ke2)

	ke2.ServerMac = serverMac

	return clientMac, sessionSecret
}

// VerifyClientMac verifies the authentication tag contained in ke3.
func VerifyClientMac(conf *internal.Configuration, ke3 *message.KE3, expectedClientMac []byte) bool {
	return conf.MAC.Equal(expectedClientMac, ke3.ClientMac)
}
