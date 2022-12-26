// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"crypto"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	group "github.com/bytemare/crypto"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// helper functions

type configuration struct {
	curve elliptic.Curve
	conf  *opaque.Configuration
	name  string
}

var configurationTable = []configuration{
	{
		name:  "Ristretto255",
		conf:  opaque.DefaultConfiguration(),
		curve: nil,
	},
	{
		name: "P256Sha256",
		conf: &opaque.Configuration{
			OPRF: opaque.P256Sha256,
			KDF:  crypto.SHA256,
			MAC:  crypto.SHA256,
			Hash: crypto.SHA256,
			KSF:  ksf.Scrypt,
			AKE:  opaque.P256Sha256,
		},
		curve: elliptic.P256(),
	},
	{
		name: "P384Sha512",
		conf: &opaque.Configuration{
			OPRF: opaque.P384Sha512,
			KDF:  crypto.SHA512,
			MAC:  crypto.SHA512,
			Hash: crypto.SHA512,
			KSF:  ksf.Scrypt,
			AKE:  opaque.P384Sha512,
		},
		curve: elliptic.P384(),
	},
	{
		name: "P521Sha512",
		conf: &opaque.Configuration{
			OPRF: opaque.P521Sha512,
			KDF:  crypto.SHA512,
			MAC:  crypto.SHA512,
			Hash: crypto.SHA512,
			KSF:  ksf.Scrypt,
			AKE:  opaque.P521Sha512,
		},
		curve: elliptic.P521(),
	},
}

func testAll(t *testing.T, f func(*testing.T, *configuration)) {
	for _, test := range configurationTable {
		t.Run(test.name, func(t *testing.T) {
			f(t, &test)
		})
	}
}

func getBadRistrettoScalar() []byte {
	a := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBadRistrettoElement() []byte {
	a := "2a292df7e32cababbd9de088d1d1abec9fc0440f637ed2fba145094dc14bea08"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBad25519Element() []byte {
	a := "efffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func getBad25519Scalar() []byte {
	a := "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000011"
	decoded, _ := hex.DecodeString(a)

	return decoded
}

func badScalar(t *testing.T, g group.Group, curve elliptic.Curve) []byte {
	order := curve.Params().P
	exceeded := new(big.Int).Add(order, big.NewInt(2)).Bytes()

	err := g.NewScalar().Decode(exceeded)
	if err == nil {
		t.Errorf("Exceeding order did not yield an error for group %s", g)
	}

	return exceeded
}

func getBadNistElement(t *testing.T, id group.Group) []byte {
	size := encoding.PointLength[id]
	element := internal.RandomBytes(size)
	// detag compression
	element[0] = 4

	// test if invalid compression is detected
	err := id.NewElement().Decode(element)
	if err == nil {
		t.Errorf("detagged compressed point did not yield an error for group %s", id)
	}

	return element
}

func getBadElement(t *testing.T, c *configuration) []byte {
	switch c.conf.AKE {
	case opaque.RistrettoSha512:
		return getBadRistrettoElement()
	default:
		return getBadNistElement(t, group.Group(c.conf.AKE))
	}
}

func getBadScalar(t *testing.T, c *configuration) []byte {
	switch c.conf.AKE {
	case opaque.RistrettoSha512:
		return getBadRistrettoScalar()
	default:
		return badScalar(t, oprf.Ciphersuite(c.conf.AKE).Group(), c.curve)
	}
}

func buildRecord(
	credID, oprfSeed, password, pks []byte,
	client *opaque.Client,
	server *opaque.Server,
) *opaque.ClientRecord {
	conf := server.GetConf()
	r1 := client.RegistrationInit(password)

	pk := conf.Group.NewElement()
	if err := pk.Decode(pks); err != nil {
		panic(err)
	}

	r2 := server.RegistrationResponse(r1, pk, credID, oprfSeed)
	r3, _ := client.RegistrationFinalize(r2)

	return &opaque.ClientRecord{
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
		RegistrationRecord:   r3,
		TestMaskNonce:        nil,
	}
}

func xorResponse(c *internal.Configuration, key, nonce, in []byte) []byte {
	pad := c.KDF.Expand(
		key,
		encoding.SuffixString(nonce, tag.CredentialResponsePad),
		encoding.PointLength[c.Group]+c.EnvelopeSize,
	)

	dst := make([]byte, len(pad))

	// if the size is fixed, we could unroll the loop
	for i, r := range pad {
		dst[i] = r ^ in[i]
	}

	return dst
}

func buildPRK(client *opaque.Client, evaluation *group.Element) ([]byte, error) {
	conf := client.GetConf()
	unblinded := client.OPRF.Finalize(evaluation)
	hardened := conf.KSF.Harden(unblinded, nil, conf.OPRFPointLength)

	return conf.KDF.Extract(nil, encoding.Concat(unblinded, hardened)), nil
}

func getEnvelope(client *opaque.Client, ke2 *message.KE2) (*keyrecovery.Envelope, []byte, error) {
	conf := client.GetConf()

	randomizedPwd, err := buildPRK(client, ke2.EvaluatedMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	maskingKey := conf.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), conf.KDF.Size())
	clear := xorResponse(conf, maskingKey, ke2.MaskingNonce, ke2.MaskedResponse)
	e := clear[encoding.PointLength[conf.Group]:]

	env := &keyrecovery.Envelope{
		Nonce:   e[:conf.NonceLen],
		AuthTag: e[conf.NonceLen:],
	}

	return env, randomizedPwd, nil
}
