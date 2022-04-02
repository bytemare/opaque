package opaque_test

import (
	"errors"
	"log"
	"strings"
	"testing"

	H2C "github.com/armfazh/h2c-go-ref"
	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
)

var (
	errInvalidStateLength = errors.New("invalid state length")
	errStateExists        = errors.New("existing state is not empty")
)

/*
	The following tests look for failing conditions.
*/

func TestServer_BadRegistrationRequest(t *testing.T) {
	/*
		Error in OPRF
		- client blinded element invalid point encoding
	*/
	err1 := "invalid message length"
	err2 := "blinded data is an invalid point"

	for i, e := range confs {
		server, _ := e.Conf.Server()
		if _, err := server.Deserialize.RegistrationRequest(nil); err == nil || !strings.HasPrefix(err.Error(), err1) {
			t.Fatalf("#%d - expected error. Got %v", i, err)
		}

		bad := getBadElement(t, e)
		if _, err := server.Deserialize.RegistrationRequest(bad); err == nil || !strings.HasPrefix(err.Error(), err2) {
			t.Fatalf("#%d - expected error. Got %v", i, err)
		}
	}
}

func TestIdentity(t *testing.T) {
	g := group.P256Sha256
	log.Printf("Group: %v", g)
	id := g.Identity()
	log.Printf("Id: %v / %v / %v", id, id.Point.IsIdentity(), id.Point)
	h, _ := H2C.P256_XMDSHA256_SSWU_RO_.Get(nil)
	x := h.GetCurve().Identity().X()
	y := h.GetCurve().Identity().Y()
	log.Printf("\n%v\n%v", x, y)
}

func TestServerInit_InvalidPublicKey(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		sk, _ := conf.Conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())

		expected := "input server public key's length is invalid"
		if _, err := server.LoginInit(nil, nil, sk, nil, oprfSeed, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil pubkey - got %s", err)
		}

		expected = "invalid server public key: "
		if _, err := server.LoginInit(nil, nil, sk, getBadElement(t, conf), oprfSeed, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad secret key - got %s", err)
		}

		expected = "invalid server public key: pks is identity point"
		log.Printf("id : %v", server.GetConf().Group)
		identity := server.GetConf().Group.Identity().Bytes()
		if _, err := server.LoginInit(nil, nil, sk, identity, oprfSeed, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidOPRFSeedLength(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		sk, pk := conf.Conf.KeyGen()
		expected := opaque.ErrInvalidOPRFSeedLength

		if _, err := server.LoginInit(nil, nil, sk, pk, nil, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on nil seed - got %s", err)
		}

		seed := internal.RandomBytes(conf.Conf.Hash.Size() - 1)
		if _, err := server.LoginInit(nil, nil, sk, pk, seed, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on bad seed - got %s", err)
		}

		seed = internal.RandomBytes(conf.Conf.Hash.Size() + 1)
		if _, err := server.LoginInit(nil, nil, sk, pk, seed, nil); err == nil || !errors.Is(err, expected) {
			t.Fatalf("expected error on bad seed - got %s", err)
		}
	}
}

func TestServerInit_NilSecretKey(t *testing.T) {
	/*
		Nil server secret key
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		_, pk := conf.Conf.KeyGen()
		expected := "invalid server secret key: "

		if _, err := server.LoginInit(nil, nil, nil, pk, nil, nil); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidEnvelope(t *testing.T) {
	/*
		Record envelope of invalid length
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		sk, pk := conf.Conf.KeyGen()
		oprfSeed := internal.RandomBytes(conf.Conf.Hash.Size())
		client, _ := conf.Conf.Client()
		rec := buildRecord(internal.RandomBytes(32), oprfSeed, []byte("yo"), pk, client, server)
		rec.Envelope = internal.RandomBytes(15)

		expected := "record has invalid envelope length"
		if _, err := server.LoginInit(nil, nil, sk, pk, oprfSeed, rec); err == nil ||
			!strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidData(t *testing.T) {
	/*
		Invalid OPRF data in KE1
	*/
	for _, conf := range confs {
		server, _ := conf.Conf.Server()
		ke1 := encoding.Concatenate(
			getBadElement(t, conf),
			internal.RandomBytes(server.GetConf().NonceLen),
			internal.RandomBytes(server.GetConf().AkePointLength),
		)
		expected := "blinded data is an invalid point"
		if _, err := server.Deserialize.KE1(ke1); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad oprf request - got %s", err)
		}
	}
}

func TestServerInit_InvalidEPKU(t *testing.T) {
	/*
		Invalid EPKU in KE1
	*/
	rec := &opaque.ClientRecord{
		CredentialIdentifier: internal.RandomBytes(32),
		ClientIdentity:       nil,
		RegistrationRecord: &message.RegistrationRecord{
			MaskingKey: internal.RandomBytes(32),
		},
		TestMaskNonce: nil,
	}

	for _, conf := range confs {
		rec.Envelope = opaque.GetFakeEnvelope(conf.Conf)
		server, _ := conf.Conf.Server()
		client, _ := conf.Conf.Client()
		ke1 := client.LoginInit([]byte("yo")).Serialize()
		badke1 := encoding.Concat(
			ke1[:server.GetConf().OPRFPointLength+server.GetConf().NonceLen],
			getBadElement(t, conf),
		)
		expected := "invalid ephemeral client public key"
		if _, err := server.Deserialize.KE1(badke1); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad epku - got %s", err)
		}
	}
}

func TestServerFinish_InvalidKE3Mac(t *testing.T) {
	/*
		ke3 mac is invalid
	*/
	conf := opaque.DefaultConfiguration()
	credId := internal.RandomBytes(32)
	oprfSeed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ := conf.Server()
	sk, pk := conf.KeyGen()
	rec := buildRecord(credId, oprfSeed, []byte("yo"), pk, client, server)
	ke1 := client.LoginInit([]byte("yo"))
	ke2, err := server.LoginInit(ke1, nil, sk, pk, oprfSeed, rec)
	if err != nil {
		t.Fatal(err)
	}
	ke3, _, err := client.LoginFinish(nil, nil, ke2)
	if err != nil {
		t.Fatal(err)
	}
	ke3.Mac[0] = ^ke3.Mac[0]

	expected := opaque.ErrAkeInvalidClientMac
	if err := server.LoginFinish(ke3); err == nil || err.Error() != expected.Error() {
		t.Fatalf("expected error on invalid mac - got %v", err)
	}
}

func TestServerSetAKEState_InvalidInput(t *testing.T) {
	conf := opaque.DefaultConfiguration()

	/*
		Test an invalid state
	*/

	buf := internal.RandomBytes(conf.MAC.Size() + conf.KDF.Size() + 1)

	server, _ := conf.Server()
	if err := server.SetAKEState(buf); err == nil || err.Error() != errInvalidStateLength.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errInvalidStateLength, err)
	}

	/*
		A state already exists.
	*/

	credId := internal.RandomBytes(32)
	seed := internal.RandomBytes(conf.Hash.Size())
	client, _ := conf.Client()
	server, _ = conf.Server()
	sk, pk := conf.KeyGen()
	rec := buildRecord(credId, seed, []byte("yo"), pk, client, server)
	ke1 := client.LoginInit([]byte("yo"))
	_, _ = server.LoginInit(ke1, nil, sk, pk, seed, rec)
	state := server.SerializeState()
	if err := server.SetAKEState(state); err == nil || err.Error() != errStateExists.Error() {
		t.Fatalf("Expected error for SetAKEState. want %q, got %q", errStateExists, err)
	}
}
