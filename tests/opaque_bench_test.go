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
)

// BenchmarkRegistration measures client/server registration flow.
func BenchmarkRegistration(b *testing.B) {
	conf := configurationTable[0]
	server, err := conf.conf.Server()
	if err != nil {
		b.Fatal(err)
	}
	sk, pk := conf.conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil,
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client, err := conf.conf.Client()
		if err != nil {
			b.Fatal(err)
		}
		r1, err := client.RegistrationInit(password)
		if err != nil {
			b.Fatal(err)
		}
		r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := client.RegistrationFinalize(r2, nil, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLogin measures end-to-end login flow.
func BenchmarkLogin(b *testing.B) {
	conf := configurationTable[0]
	client, err := conf.conf.Client()
	if err != nil {
		b.Fatal(err)
	}
	server, err := conf.conf.Server()
	if err != nil {
		b.Fatal(err)
	}
	sk, pk := conf.conf.KeyGen()
	skm := &opaque.ServerKeyMaterial{
		Identity:       nil,
		PrivateKey:     sk,
		PublicKeyBytes: pk.Encode(),
		OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
	}
	if err := server.SetKeyMaterial(skm); err != nil {
		b.Fatal(err)
	}

	// Registration once to obtain a record
	r1, err := client.RegistrationInit(password)
	if err != nil {
		b.Fatal(err)
	}
	r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
	if err != nil {
		b.Fatal(err)
	}
	r3, _, err := client.RegistrationFinalize(r2, nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	record := &opaque.ClientRecord{RegistrationRecord: r3, CredentialIdentifier: credentialIdentifier}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Fresh client state per iteration
		c, err := conf.conf.Client()
		if err != nil {
			b.Fatal(err)
		}
		ke1, err := c.GenerateKE1(password)
		if err != nil {
			b.Fatal(err)
		}
		ke2, out, err := server.GenerateKE2(ke1, record)
		if err != nil {
			b.Fatal(err)
		}
		ke3, _, _, err := c.GenerateKE3(ke2, nil, nil)
		if err != nil {
			b.Fatal(err)
		}
		if err := server.LoginFinish(ke3, out.ClientMAC); err != nil {
			b.Fatal(err)
		}
	}
}

// Per-suite benchmarks
func BenchmarkRegistrationSuites(b *testing.B) {
	for _, conf := range configurationTable {
		conf := conf
		b.Run(conf.name, func(b *testing.B) {
			server, err := conf.conf.Server()
			if err != nil {
				b.Fatal(err)
			}
			sk, pk := conf.conf.KeyGen()
			skm := &opaque.ServerKeyMaterial{
				Identity:       nil,
				PrivateKey:     sk,
				PublicKeyBytes: pk.Encode(),
				OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
			}
			if err := server.SetKeyMaterial(skm); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				client, err := conf.conf.Client()
				if err != nil {
					b.Fatal(err)
				}
				r1, err := client.RegistrationInit(password)
				if err != nil {
					b.Fatal(err)
				}
				r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
				if err != nil {
					b.Fatal(err)
				}
				if _, _, err := client.RegistrationFinalize(r2, nil, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLoginSuites(b *testing.B) {
	for _, conf := range configurationTable {
		conf := conf
		b.Run(conf.name, func(b *testing.B) {
			// Setup server
			server, err := conf.conf.Server()
			if err != nil {
				b.Fatal(err)
			}
			sk, pk := conf.conf.KeyGen()
			skm := &opaque.ServerKeyMaterial{
				Identity:       nil,
				PrivateKey:     sk,
				PublicKeyBytes: pk.Encode(),
				OPRFGlobalSeed: internal.RandomBytes(conf.conf.Hash.Size()),
			}
			if err := server.SetKeyMaterial(skm); err != nil {
				b.Fatal(err)
			}

			// Registration for record
			client, err := conf.conf.Client()
			if err != nil {
				b.Fatal(err)
			}
			r1, err := client.RegistrationInit(password)
			if err != nil {
				b.Fatal(err)
			}
			r2, err := server.RegistrationResponse(r1, credentialIdentifier, nil)
			if err != nil {
				b.Fatal(err)
			}
			r3, _, err := client.RegistrationFinalize(r2, nil, nil)
			if err != nil {
				b.Fatal(err)
			}
			record := &opaque.ClientRecord{RegistrationRecord: r3, CredentialIdentifier: credentialIdentifier}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c, err := conf.conf.Client()
				if err != nil {
					b.Fatal(err)
				}
				ke1, err := c.GenerateKE1(password)
				if err != nil {
					b.Fatal(err)
				}
				ke2, out, err := server.GenerateKE2(ke1, record)
				if err != nil {
					b.Fatal(err)
				}
				ke3, _, _, err := c.GenerateKE3(ke2, nil, nil)
				if err != nil {
					b.Fatal(err)
				}
				if err := server.LoginFinish(ke3, out.ClientMAC); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
