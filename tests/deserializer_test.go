// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"encoding/hex"
	"errors"
	"testing"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
)

const testErrValidConf = "unexpected error on valid configuration: %v"

var errInvalidMessageLength = errors.New("invalid message length for the configuration")

/*
	Message Deserialization
*/

func TestDeserializer(t *testing.T) {
	// Test valid configurations
	testAll(t, func(t2 *testing.T, conf *configuration) {
		if _, err := conf.conf.Deserializer(); err != nil {
			t.Fatalf(testErrValidConf, err)
		}
	})

	// Test for an invalid configuration.
	conf := &opaque.Configuration{
		OPRF:    0,
		KDF:     0,
		MAC:     0,
		Hash:    0,
		KSF:     0,
		AKE:     0,
		Context: nil,
	}

	if _, err := conf.Deserializer(); err == nil {
		t.Fatal("expected error on invalid configuration")
	}
}

func TestDeserializeRegistrationRequest(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server, _ := c.Server()
	conf := server.GetConf()
	length := conf.OPRF.Group().ElementLength() + 1
	if _, err := server.Deserialize.RegistrationRequest(internal.RandomBytes(length)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.Deserialize.RegistrationRequest(internal.RandomBytes(length)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationResponse(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server, _ := c.Server()
	conf := server.GetConf()
	length := conf.OPRF.Group().ElementLength() + conf.Group.ElementLength() + 1
	if _, err := server.Deserialize.RegistrationResponse(internal.RandomBytes(length)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.Deserialize.RegistrationResponse(internal.RandomBytes(length)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationRecord(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		server, err := conf.conf.Server()
		if err != nil {
			t.Fatal(err)
		}
		c := server.GetConf()
		length := c.Group.ElementLength() + c.Hash.Size() + c.EnvelopeSize + 1
		if _, err := server.Deserialize.RegistrationRecord(internal.RandomBytes(length)); err == nil ||
			err.Error() != errInvalidMessageLength.Error() {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
		}

		badPKu := getBadElement(t, conf)
		rec := encoding.Concat(badPKu, internal.RandomBytes(c.Hash.Size()+c.EnvelopeSize))

		expect := "invalid client public key"
		if _, err := server.Deserialize.RegistrationRecord(rec); err == nil || err.Error() != expect {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", expect, err)
		}

		client, err := conf.conf.Client()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Deserialize.RegistrationRecord(internal.RandomBytes(length)); err == nil ||
			err.Error() != errInvalidMessageLength.Error() {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
		}
	})
}

func TestDeserializeKE1(t *testing.T) {
	c := opaque.DefaultConfiguration()
	g := group.Group(c.AKE)
	ke1Length := g.ElementLength() + internal.NonceLength + g.ElementLength()

	server, _ := c.Server()
	if _, err := server.Deserialize.KE1(internal.RandomBytes(ke1Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.Deserialize.KE1(internal.RandomBytes(ke1Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE2(t *testing.T) {
	c := opaque.DefaultConfiguration()

	client, _ := c.Client()
	conf := client.GetConf()
	ke2Length := conf.OPRF.Group().
		ElementLength() +
		2*conf.NonceLen + 2*conf.Group.ElementLength() + conf.EnvelopeSize + conf.MAC.Size()
	if _, err := client.Deserialize.KE2(internal.RandomBytes(ke2Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	server, _ := c.Server()
	conf = server.GetConf()
	ke2Length = conf.OPRF.Group().
		ElementLength() +
		2*conf.NonceLen + 2*conf.Group.ElementLength() + conf.EnvelopeSize + conf.MAC.Size()
	if _, err := server.Deserialize.KE2(internal.RandomBytes(ke2Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE3(t *testing.T) {
	c := opaque.DefaultConfiguration()
	ke3Length := c.MAC.Size()

	server, _ := c.Server()
	if _, err := server.Deserialize.KE3(internal.RandomBytes(ke3Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client, _ := c.Client()
	if _, err := client.Deserialize.KE3(internal.RandomBytes(ke3Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDecodeAkePrivateKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		badKey := getBadScalar(t, conf)

		des, err := conf.conf.Deserializer()
		if err != nil {
			t.Fatalf(testErrValidConf, err)
		}

		if _, err := des.DecodeAkePrivateKey(badKey); err == nil {
			t.Fatalf("expect error on invalid private key. Group %v, key %v",
				conf.conf.AKE,
				hex.EncodeToString(badKey),
			)
		}
	})
}

func TestDecodeAkePublicKey(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		badKey := getBadElement(t, conf)

		des, err := conf.conf.Deserializer()
		if err != nil {
			t.Fatalf(testErrValidConf, err)
		}

		if _, err := des.DecodeAkePublicKey(badKey); err == nil {
			t.Fatalf("expect error on invalid public key. Group %v, key %v",
				conf.conf.AKE,
				hex.EncodeToString(badKey),
			)
		}
	})
}
