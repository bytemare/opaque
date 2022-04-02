package opaque_test

import (
	"errors"
	"testing"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
)

var errInvalidMessageLength = errors.New("invalid message length for the configuration")

/*
	Message Deserialization
*/

func TestDeserializeRegistrationRequest(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server, _ := c.Server()
	conf := server.GetConf()
	length := conf.OPRFPointLength + 1
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
	length := conf.OPRFPointLength + conf.AkePointLength + 1
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
	for _, e := range confs {
		server, _ := e.Conf.Server()
		conf := server.GetConf()
		length := conf.AkePointLength + conf.Hash.Size() + conf.EnvelopeSize + 1
		if _, err := server.Deserialize.RegistrationRecord(internal.RandomBytes(length)); err == nil ||
			err.Error() != errInvalidMessageLength.Error() {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
		}

		badPKu := getBadElement(t, e)
		rec := encoding.Concat(badPKu, internal.RandomBytes(conf.Hash.Size()+conf.EnvelopeSize))

		expect := "invalid client public key"
		if _, err := server.Deserialize.RegistrationRecord(rec); err == nil || err.Error() != expect {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", expect, err)
		}

		client, _ := e.Conf.Client()
		if _, err := client.Deserialize.RegistrationRecord(internal.RandomBytes(length)); err == nil ||
			err.Error() != errInvalidMessageLength.Error() {
			t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
		}
	}
}

func TestDeserializeKE1(t *testing.T) {
	c := opaque.DefaultConfiguration()
	g := group.Group(c.AKE)
	ke1Length := encoding.PointLength[g] + internal.NonceLength + encoding.PointLength[g]

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
	ke2Length := conf.OPRFPointLength + 2*conf.NonceLen + 2*conf.AkePointLength + conf.EnvelopeSize + conf.MAC.Size()
	if _, err := client.Deserialize.KE2(internal.RandomBytes(ke2Length + 1)); err == nil ||
		err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	server, _ := c.Server()
	conf = server.GetConf()
	ke2Length = conf.OPRFPointLength + 2*conf.NonceLen + 2*conf.AkePointLength + conf.EnvelopeSize + conf.MAC.Size()
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
