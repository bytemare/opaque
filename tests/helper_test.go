// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
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

	group "github.com/bytemare/ecc"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/keyrecovery"
	internalKSF "github.com/bytemare/opaque/internal/ksf"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	for _, c := range configurationTable {
		var err error
		c.internal, err = toInternal(c.conf)
		if err != nil {
			panic(err)
		}
	}
}

// helper functions

type configuration struct {
	curve    elliptic.Curve
	conf     *opaque.Configuration
	internal *internal.Configuration
	name     string
}

func verify(c *opaque.Configuration) error {
	if !c.OPRF.Available() || !c.OPRF.OPRF().Available() {
		return opaque.ErrInvalidOPRFid
	}

	if !c.AKE.Available() || !c.AKE.Group().Available() {
		return opaque.ErrInvalidAKEid
	}

	if !internal.IsHashFunctionValid(c.KDF) {
		return opaque.ErrInvalidKDFid
	}

	if !internal.IsHashFunctionValid(c.MAC) {
		return opaque.ErrInvalidMACid
	}

	if !internal.IsHashFunctionValid(c.Hash) {
		return opaque.ErrInvalidHASHid
	}

	if c.KSF != 0 && !c.KSF.Available() {
		return opaque.ErrInvalidKSFid
	}

	return nil
}

func toInternal(c *opaque.Configuration) (*internal.Configuration, error) {
	if err := verify(c); err != nil {
		return nil, err
	}

	g := c.AKE.Group()
	o := c.OPRF.OPRF()
	mac := internal.NewMac(c.MAC)
	return &internal.Configuration{
		OPRF:         o,
		Group:        g,
		KSF:          internalKSF.NewKSF(c.KSF),
		KDF:          internal.NewKDF(c.KDF),
		MAC:          mac,
		Hash:         internal.NewHash(c.Hash),
		NonceLen:     internal.NonceLength,
		EnvelopeSize: internal.NonceLength + mac.Size(),
		Context:      c.Context,
	}, nil
}

var configurationTable = []*configuration{
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
			KSF:  ksf.Argon2id,
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
			KSF:  ksf.Argon2id,
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
			KSF:  ksf.Argon2id,
			AKE:  opaque.P521Sha512,
		},
		curve: elliptic.P521(),
	},
}

func testAll(t *testing.T, f func(*testing.T, *configuration)) {
	for _, test := range configurationTable {
		t.Run(test.name, func(t *testing.T) {
			f(t, test)
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
	t.Helper()
	order := curve.Params().P
	exceeded := new(big.Int).Add(order, big.NewInt(2)).Bytes()

	err := g.NewScalar().Decode(exceeded)
	if err == nil {
		t.Errorf("Exceeding order did not yield an error for group %s", g)
	}

	return exceeded
}

func getBadNistElement(t *testing.T, id group.Group) []byte {
	size := id.ElementLength()
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
		return badScalar(t, oprf.IDFromGroup(group.Group(c.conf.AKE)).Group(), c.curve)
	}
}

func buildRecord(
	conf *opaque.Configuration,
	serverKM *opaque.ServerKeyMaterial,
	serverPublicKey, credID, password []byte,
) (*opaque.ClientRecord, error) {
	client, err := conf.Client()
	if err != nil {
		return nil, err
	}

	server, err := conf.Server()
	if err != nil {
		return nil, err
	}

	if err := server.SetKeyMaterial(serverKM); err != nil {
		return nil, fmt.Errorf("setting server key material: %w", err)
	}

	r1, err := client.RegistrationInit(password)
	if err != nil {
		return nil, err
	}

	r2, err := server.RegistrationResponse(r1, serverPublicKey, credID, nil)
	if err != nil {
		return nil, err
	}

	r3, _, err := client.RegistrationFinalize(r2, nil, nil)
	if err != nil {
		return nil, err
	}

	return &opaque.ClientRecord{
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
		RegistrationRecord:   r3,
	}, nil
}

func xorResponse(c *internal.Configuration, key, nonce, in []byte) []byte {
	pad := c.KDF.Expand(
		key,
		encoding.SuffixString(nonce, tag.CredentialResponsePad),
		c.Group.ElementLength()+c.EnvelopeSize,
	)

	dst := make([]byte, len(pad))

	// if the size is fixed, we could unroll the loop
	for i, r := range pad {
		dst[i] = r ^ in[i]
	}

	return dst
}

func buildPRK(
	conf *internal.Configuration,
	blind *group.Scalar,
	password []byte,
	evaluation *group.Element,
) ([]byte, error) {
	unblinded := conf.OPRF.Finalize(blind, password, evaluation)
	hardened := conf.KSF.Harden(unblinded, nil, conf.OPRF.Group().ElementLength())

	return conf.KDF.Extract(nil, encoding.Concat(unblinded, hardened)), nil
}

func getEnvelope(
	conf *internal.Configuration,
	blind *group.Scalar,
	password []byte,
	ke2 *message.KE2,
) (*keyrecovery.Envelope, []byte, error) {
	randomizedPassword, err := buildPRK(conf, blind, password, ke2.EvaluatedMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	maskingKey := conf.KDF.Expand(randomizedPassword, []byte(tag.MaskingKey), conf.KDF.Size())
	clearText := xorResponse(conf, maskingKey, ke2.MaskingNonce, ke2.MaskedResponse)
	e := clearText[conf.Group.ElementLength():]

	env := &keyrecovery.Envelope{
		Nonce:   e[:conf.NonceLen],
		AuthTag: e[conf.NonceLen:],
	}

	return env, randomizedPassword, nil
}
