// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"bytes"
	"crypto"
	"fmt"
	"log"

	"github.com/bytemare/crypto/ksf"

	"github.com/bytemare/opaque"
)

func isSameConf(a, b *opaque.Configuration) bool {
	if a.OPRF != b.OPRF {
		return false
	}
	if a.KDF != b.KDF {
		return false
	}
	if a.MAC != b.MAC {
		return false
	}
	if a.Hash != b.Hash {
		return false
	}
	if a.KSF != b.KSF {
		return false
	}
	if a.AKE != b.AKE {
		return false
	}

	return bytes.Equal(a.Context, b.Context)
}

// Example_configuration shows how to set up the same configuration in two different ways and hot to serialize and
// deserialize a configuration.
func Example_configuration() {
	// Note that applications must use the same configuration throughout their lifecycle, and be the same on both client
	// and server. The two following configurations are the same, and are recommended.

	defaultConf := opaque.DefaultConfiguration()

	customConf := &opaque.Configuration{
		OPRF:    opaque.RistrettoSha512,
		KDF:     crypto.SHA512,
		MAC:     crypto.SHA512,
		Hash:    crypto.SHA512,
		KSF:     ksf.Scrypt,
		AKE:     opaque.RistrettoSha512,
		Context: nil,
	}

	if !isSameConf(defaultConf, customConf) {
		log.Fatalln("Oh no! Configurations differ!")
	}

	// A configuration can be hardcoded in an app with this 8-byte array, and decoded at runtime.
	encoded := defaultConf.Serialize()

	conf, err := opaque.DeserializeConfiguration(encoded)
	if err != nil {
		log.Fatalf("Oh no! Decoding the configurations failed! %v", err)
	}

	if !isSameConf(defaultConf, conf) {
		log.Fatalln("Oh no! Something went wrong in decoding the configuration!")
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}

// Example_clientSetup demonstrates how to create a client role from a configuration.
func Example_clientSetup() {
	// First, load or instantiate a configuration.
	conf := opaque.DefaultConfiguration()

	// On each protocol run, the following produces a client role.
	client, err := conf.Client()
	if client == nil || err != nil {
		log.Fatalf("Oh no! Something went wrong setting up the client! %v", err)
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}

// Example_serverSetup demonstrates how to create a server role from a configuration.
func Example_serverSetup() {
	// First, load or instantiate a configuration.
	conf := opaque.DefaultConfiguration()

	// The very first time you set up your app, you need to create the following values and securely store them.
	serverPrivateKey, serverPublicKey := conf.KeyGen()
	secretOprfSeed := conf.GenerateOPRFSeed()
	if serverPrivateKey == nil || serverPublicKey == nil || secretOprfSeed == nil {
		log.Fatalf("Oh no! Something went wrong setting up the server secrets!")
	}

	// Then, on each protocol run, the following produces a server role.
	server, err := conf.Server()
	if server == nil || err != nil {
		log.Fatalf("Oh no! Something went wrong setting up the server! %v", err)
	}

	fmt.Println("OPAQUE configuration is easy!")

	// Output: OPAQUE configuration is easy!
}
