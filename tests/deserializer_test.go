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

	group "github.com/bytemare/ecc"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
)

const testErrValidConf = "unexpected error on valid configuration: %v"

var errInvalidMessageLength = internal.ErrInvalidMessageLength

func getDeserializer(t *testing.T, c *opaque.Configuration) *opaque.Deserializer {
	t.Helper()

	d, err := c.Deserializer()
	if err != nil {
		t.Fatal(err)
	}

	return d
}

/*
	Message Deserialization
*/

func TestDeserializer_New(t *testing.T) {
	// Test valid configurations
	testAll(t, func(t2 *testing.T, conf *configuration) {
		if _, err := conf.conf.Deserializer(); err != nil {
			t.Fatalf(testErrValidConf, err)
		}
	})

	// Test for an invalid configuration.
	conf := &opaque.Configuration{
		OPRF:    0,
		AKE:     0,
		KSF:     0,
		KDF:     0,
		MAC:     0,
		Hash:    0,
		Context: nil,
	}

	if _, err := conf.Deserializer(); err == nil {
		t.Fatal("expected error on invalid configuration")
	}
}

func TestDeserializer_RegistrationRequest_InvalidLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		length := c.OPRF.Group().ElementLength() + 1
		d := getDeserializer(t, c)

		expectErrors(t, func() error {
			_, err := d.RegistrationRequest(internal.RandomBytes(length))
			return err
		}, opaque.ErrRegistrationRequest, errInvalidMessageLength)
	})
}

func TestDeserializer_RegistrationResponse_InvalidLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		length := c.OPRF.Group().ElementLength() + c.AKE.Group().ElementLength() + 1
		d := getDeserializer(t, c)

		expectErrors(t, func() error {
			_, err := d.RegistrationResponse(internal.RandomBytes(length))
			return err
		}, opaque.ErrRegistrationResponse, errInvalidMessageLength)
	})
}

func TestDeserialize_RegistrationRecord_InvalidLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		length := c.AKE.Group().ElementLength() + c.Hash.Size() + conf.internal.EnvelopeSize + 1
		d := getDeserializer(t, conf.conf)

		expectErrors(t, func() error {
			_, err := d.RegistrationRecord(internal.RandomBytes(length))
			return err
		}, opaque.ErrRegistrationRecord, errInvalidMessageLength)
	})
}

func TestDeserializer_KE1_InvalidLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		g := group.Group(c.AKE)
		ke1Length := g.ElementLength() + internal.NonceLength + g.ElementLength()

		d := getDeserializer(t, c)

		expectErrors(t, func() error {
			_, err := d.KE1(internal.RandomBytes(ke1Length + 1))
			return err
		}, opaque.ErrKE1, errInvalidMessageLength)
	})
}

func TestDeserializer_KE2_InvalidLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		ke2Length := c.OPRF.Group().ElementLength() +
			2*conf.internal.NonceLen + 2*conf.internal.Group.ElementLength() + conf.internal.EnvelopeSize + conf.internal.MAC.Size()

		d := getDeserializer(t, c)

		expectErrors(t, func() error {
			_, err := d.KE1(internal.RandomBytes(ke2Length + 1))
			return err
		}, opaque.ErrKE2, errInvalidMessageLength)
	})
}

func TestDeserializer_KE3_InvalidLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		c := conf.conf
		ke3Length := c.MAC.Size()

		d := getDeserializer(t, c)

		expectErrors(t, func() error {
			_, err := d.KE1(internal.RandomBytes(ke3Length + 1))
			return err
		}, opaque.ErrKE3, errInvalidMessageLength)
	})
}

/*
	Decode Keys
*/

func TestDecodeAkePrivateKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		key := conf.conf.AKE.Group().NewScalar().Random()

		d := getDeserializer(t, conf.conf)

		if _, err := d.DecodePrivateKey(key.Encode()); err != nil {
			t.Fatalf("unexpected error on valid private key. Group %v, key %v",
				conf.conf.AKE,
				key.Hex(),
			)
		}
	})
}

func TestDecodeBadAkePrivateKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		badKey := getBadScalar(t, conf)
		d := getDeserializer(t, conf.conf)

		expectErrors(t, func() error {
			_, err := d.DecodePrivateKey(badKey)
			return err
		}, internal.ErrInvalidPrivateKey)
	})
}

func TestDecodeAkePublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		s := conf.conf.AKE.Group().NewScalar().Random()
		p := conf.conf.AKE.Group().Base().Multiply(s)

		d := getDeserializer(t, conf.conf)

		if _, err := d.DecodePublicKey(p.Encode()); err != nil {
			t.Fatalf("unexpected error on valid public key. Group %v, element %v",
				conf.conf.AKE,
				p.Hex(),
			)
		}
	})
}

func TestDecodeBadAkePublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		badKey := getBadElement(t, conf)

		d := getDeserializer(t, conf.conf)

		expectErrors(t, func() error {
			_, err := d.DecodePublicKey(badKey)
			return err
		}, internal.ErrInvalidPublicKey)
	})
}
