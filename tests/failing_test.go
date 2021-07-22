package opaque

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/voprf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/envelope"
	message2 "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/internal/tag"
	"github.com/bytemare/opaque/message"
)

var errInvalidMessageLength = errors.New("invalid message length")

func TestDeserializeRegistrationRequest(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server := c.Server()
	length := server.OPRFPointLength + 1
	if _, err := server.DeserializeRegistrationRequest(utils.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeRegistrationRequest(utils.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationResponse(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server := c.Server()
	length := server.OPRFPointLength + server.AkePointLength + 1
	if _, err := server.DeserializeRegistrationResponse(utils.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeRegistrationResponse(utils.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeRegistrationUpload(t *testing.T) {
	c := opaque.DefaultConfiguration()

	server := c.Server()
	length := server.AkePointLength + server.Hash.Size() + server.EnvelopeSize + 1
	if _, err := server.DeserializeRegistrationUpload(utils.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeRegistrationUpload(utils.RandomBytes(length)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeRegistrationRequest. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE1(t *testing.T) {
	c := opaque.DefaultConfiguration()
	group := voprf.Ciphersuite(c.OprfGroup).Group()
	ke1Length := encoding.PointLength[group] + c.NonceLen + encoding.PointLength[group]

	server := c.Server()
	if _, err := server.DeserializeKE1(utils.RandomBytes(ke1Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeKE1(utils.RandomBytes(ke1Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE2(t *testing.T) {
	c := opaque.DefaultConfiguration()

	client := c.Client()
	ke2Length := client.OPRFPointLength + 2*client.NonceLen + 2*client.AkePointLength + client.EnvelopeSize + client.MAC.Size()
	if _, err := client.DeserializeKE2(utils.RandomBytes(ke2Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	server := c.Server()
	ke2Length = server.OPRFPointLength + 2*server.NonceLen + 2*server.AkePointLength + server.EnvelopeSize + server.MAC.Size()
	if _, err := server.DeserializeKE2(utils.RandomBytes(ke2Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

func TestDeserializeKE3(t *testing.T) {
	c := opaque.DefaultConfiguration()
	ke3Length := c.MAC.Size()

	server := c.Server()
	if _, err := server.DeserializeKE3(utils.RandomBytes(ke3Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}

	client := c.Client()
	if _, err := client.DeserializeKE3(utils.RandomBytes(ke3Length + 1)); err == nil || err.Error() != errInvalidMessageLength.Error() {
		t.Fatalf("Expected error for DeserializeKE1. want %q, got %q", errInvalidMessageLength, err)
	}
}

// opaque.go

func TestDeserializeConfiguration(t *testing.T) {
	r7 := utils.RandomBytes(7)
	r9 := utils.RandomBytes(9)

	if _, err := opaque.DeserializeConfiguration(r7); !errors.Is(err, internal.ErrConfigurationInvalidLength) {
		t.Errorf("DeserializeConfiguration did not return the appropriate error for vector r7. want %q, got %q",
			internal.ErrConfigurationInvalidLength, err)
	}

	if _, err := opaque.DeserializeConfiguration(r9); !errors.Is(err, internal.ErrConfigurationInvalidLength) {
		t.Errorf("DeserializeConfiguration did not return the appropriate error for vector r9. want %q, got %q",
			internal.ErrConfigurationInvalidLength, err)
	}
}

func TestNilConfiguration(t *testing.T) {
	def := opaque.DefaultConfiguration()

	cs := voprf.Ciphersuite(def.OprfGroup)
	g := cs.Group()
	defaultConfiguration := &internal.Parameters{
		KDF:             &internal.KDF{H: def.KDF.Get()},
		MAC:             &internal.Mac{H: def.MAC.Get()},
		Hash:            &internal.Hash{H: def.Hash.Get()},
		MHF:             &internal.MHF{MHF: def.MHF.Get()},
		NonceLen:        def.NonceLen,
		OPRFPointLength: encoding.PointLength[cs.Group()],
		AkePointLength:  encoding.PointLength[g],
		OprfCiphersuite: cs,
		AKEGroup:        g,
		Context:         def.Context,
	}

	s := opaque.NewServer(nil)
	if reflect.DeepEqual(s.Parameters, defaultConfiguration) {
		t.Errorf("server did not default to correct configuration")
	}

	c := opaque.NewClient(nil)
	if reflect.DeepEqual(c.Parameters, defaultConfiguration) {
		t.Errorf("client did not default to correct configuration")
	}
}

func TestConfigurationStringers(t *testing.T) {
	/*
		1. group.String()
		2. Configuration.string()
	*/
}

// helper functions

type configuration struct {
	Conf  *opaque.Configuration
	Curve elliptic.Curve
}

var confs = []configuration{
	{
		Conf:  opaque.DefaultConfiguration(),
		Curve: nil,
	},
	{
		Conf: &opaque.Configuration{
			OprfGroup: opaque.P256Sha256,
			KDF:       hash.SHA256,
			MAC:       hash.SHA256,
			Hash:      hash.SHA256,
			MHF:       mhf.Scrypt,
			Mode:      opaque.Internal,
			AKEGroup:  opaque.P256Sha256,
			NonceLen:  32,
		},
		Curve: elliptic.P256(),
	},
	{
		Conf: &opaque.Configuration{
			OprfGroup: opaque.P384Sha512,
			KDF:       hash.SHA512,
			MAC:       hash.SHA512,
			Hash:      hash.SHA512,
			MHF:       mhf.Scrypt,
			Mode:      opaque.Internal,
			AKEGroup:  opaque.P384Sha512,
			NonceLen:  32,
		},
		Curve: elliptic.P384(),
	},
	{
		Conf: &opaque.Configuration{
			OprfGroup: opaque.P521Sha512,
			KDF:       hash.SHA512,
			MAC:       hash.SHA512,
			Hash:      hash.SHA512,
			MHF:       mhf.Scrypt,
			Mode:      opaque.Internal,
			AKEGroup:  opaque.P521Sha512,
			NonceLen:  32,
		},
		Curve: elliptic.P521(),
	},
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

func getBadNistScalar(t *testing.T, ci ciphersuite.Identifier, curve elliptic.Curve) []byte {
	order := curve.Params().P
	exceeded := order.Add(order, big.NewInt(2)).Bytes()

	_, err := ci.Get().NewScalar().Decode(exceeded)
	if err == nil {
		t.Errorf("Exceeding order did not yield an error for group %s", ci)
	}

	return exceeded
}

func getBadNistElement(t *testing.T, ci ciphersuite.Identifier) []byte {
	size := encoding.PointLength[ci]
	element := utils.RandomBytes(size)
	// detag compression
	element[0] = 4

	_, err := ci.Get().NewElement().Decode(element)
	if err == nil {
		t.Errorf("detagged compressed point did not yield an error for group %s", ci)
	}

	return element
}

func getBadElement(t *testing.T, c configuration) []byte {
	if c.Conf.OprfGroup == opaque.RistrettoSha512 {
		return getBadRistrettoElement()
	} else {
		return getBadNistElement(t, voprf.Ciphersuite(c.Conf.OprfGroup).Group())
	}
}

func getBadScalar(t *testing.T, c configuration) []byte {
	if c.Conf.OprfGroup == opaque.RistrettoSha512 {
		return getBadRistrettoScalar()
	} else {
		return getBadNistScalar(t, voprf.Ciphersuite(c.Conf.OprfGroup).Group(), c.Curve)
	}
}

func buildRecord(t *testing.T, credID, oprfSeed, password, pks []byte, client *opaque.Client, server *opaque.Server) *opaque.ClientRecord {
	r1 := client.RegistrationInit(password)
	r2, err := server.RegistrationResponse(r1, pks, credID, oprfSeed)
	if err != nil {
		t.Fatal(err)
	}

	skc, _ := client.KeyGen()
	r3, _, err := client.RegistrationFinalize(skc, &opaque.Credentials{}, r2)
	if err != nil {
		t.Fatal(err)
	}

	return &opaque.ClientRecord{
		CredentialIdentifier: credID,
		ClientIdentity:       nil,
		RegistrationUpload:   r3,
		TestMaskNonce:        nil,
	}
}

func getEnvelope(mode envelope.Mode, client *opaque.Client, ke2 *message.KE2) (*envelope.Envelope, []byte, error) {
	unblinded, err := client.Core.OprfFinalize(ke2.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := envelope.BuildPRK(client.Parameters, unblinded)
	maskingKey := client.Core.KDF.Expand(randomizedPwd, []byte(tag.MaskingKey), client.Core.Hash.Size())

	clear := client.MaskResponse(maskingKey, ke2.MaskingNonce, ke2.MaskedResponse)
	e := clear[encoding.PointLength[client.AKEGroup]:]

	// Deserialize
	innerLen := 0

	if mode == envelope.External {
		innerLen = encoding.ScalarLength[client.AKEGroup]
	}

	env := &envelope.Envelope{
		Nonce:         e[:client.NonceLen],
		InnerEnvelope: e[client.NonceLen : client.NonceLen+innerLen],
		AuthTag:       e[client.NonceLen+innerLen:],
	}

	return env, randomizedPwd, nil
}

// server.go

func TestServer_BadRegistrationRequest(t *testing.T) {
	/*
		Error in OPRF
		- client blinded element invalid point encoding
	*/
	credId := utils.RandomBytes(32)
	seed := utils.RandomBytes(32)
	terr := " RegistrationResponse: oprf evaluation: "

	for i, e := range confs {
		badRequest := &message.RegistrationRequest{Data: getBadElement(t, e)}
		server := e.Conf.Server()
		if _, err := server.RegistrationResponse(badRequest, nil, credId, seed); err == nil || !strings.HasPrefix(err.Error(), terr) {
			log.Printf("#%d - expected error. Got %v", i, err)
		}
	}
}

func TestServerInit_InvalidPublicKey(t *testing.T) {
	/*
		Nil and invalid server public key
	*/
	for _, conf := range confs {
		server := conf.Conf.Server()
		expected := "invalid server public key: "

		if _, err := server.Init(nil, nil, nil, nil, nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil pubkey - got %s", err)
		}

		if _, err := server.Init(nil, nil, nil, getBadElement(t, conf), nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad secret key - got %s", err)
		}
	}
}

func TestServerInit_NilSecretKey(t *testing.T) {
	/*
		Nil server secret key
	*/
	for _, conf := range confs {
		server := conf.Conf.Server()
		_, pk := server.KeyGen()
		expected := "invalid server secret key: "

		if _, err := server.Init(nil, nil, nil, pk, nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on nil secret key - got %s", err)
		}
	}
}

func TestServerInit_InvalidData(t *testing.T) {
	/*
		Invalid OPRF data in KE1
	*/
	seed := utils.RandomBytes(32)
	rec := &opaque.ClientRecord{
		CredentialIdentifier: utils.RandomBytes(32),
		ClientIdentity:       nil,
		RegistrationUpload: &message.RegistrationUpload{
			MaskingKey: utils.RandomBytes(32),
		},
		TestMaskNonce: nil,
	}

	for _, conf := range confs {
		server := conf.Conf.Server()
		sk, pk := server.KeyGen()
		client := conf.Conf.Client()
		ke1 := client.Init([]byte("yo"))
		ke1.CredentialRequest.Data = getBadElement(t, conf)
		expected := " credentialResponse: oprfResponse: oprf evaluation: OPRF can't evaluate input :"
		if _, err := server.Init(ke1, nil, sk, pk, seed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad oprf request - got %s", err)
		}
	}
}

func TestServerInit_InvalidEPKU(t *testing.T) {
	/*
		Invalid EPKU in KE1
	*/
	seed := utils.RandomBytes(32)
	rec := &opaque.ClientRecord{
		CredentialIdentifier: utils.RandomBytes(32),
		ClientIdentity:       nil,
		RegistrationUpload: &message.RegistrationUpload{
			MaskingKey: utils.RandomBytes(32),
		},
		TestMaskNonce: nil,
	}

	for _, conf := range confs {
		rec.Envelope = opaque.GetFakeEnvelope(conf.Conf)
		server := conf.Conf.Server()
		sk, pk := server.KeyGen()
		client := conf.Conf.Client()
		ke1 := client.Init([]byte("yo"))
		ke1.EpkU = getBadElement(t, conf)
		expected := " AKE response: decoding peer ephemeral public key:"
		if _, err := server.Init(ke1, nil, sk, pk, seed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad epku - got %s", err)
		}
	}
}

func TestServerInit_InvalidPKU(t *testing.T) {
	/*
		Invalid PKU in KE1
	*/
	seed := utils.RandomBytes(32)
	rec := &opaque.ClientRecord{
		CredentialIdentifier: utils.RandomBytes(32),
		ClientIdentity:       nil,
		RegistrationUpload: &message.RegistrationUpload{
			MaskingKey: utils.RandomBytes(32),
		},
		TestMaskNonce: nil,
	}

	for _, conf := range confs {
		rec.Envelope = opaque.GetFakeEnvelope(conf.Conf)
		server := conf.Conf.Server()
		sk, pk := server.KeyGen()
		client := conf.Conf.Client()
		ke1 := client.Init([]byte("yo"))
		rec.PublicKey = getBadElement(t, conf)
		expected := " AKE response: decoding peer public key:"
		if _, err := server.Init(ke1, nil, sk, pk, seed, rec); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error on bad epku - got %s", err)
		}
	}
}

func TestServerFinish_InvalidKE3Mac(t *testing.T) {
	/*
		ke3 mac is invalid
	*/
	conf := opaque.DefaultConfiguration()
	credId := utils.RandomBytes(32)
	seed := utils.RandomBytes(32)
	client := conf.Client()
	server := conf.Server()
	sk, pk := server.KeyGen()
	rec := buildRecord(t, credId, seed, []byte("yo"), pk, client, server)
	ke1 := client.Init([]byte("yo"))
	ke2, _ := server.Init(ke1, nil, sk, pk, seed, rec)
	ke3, _, _ := client.Finish(nil, nil, ke2)
	ke3.Mac[0] = ^ke3.Mac[0]

	expected := opaque.ErrAkeInvalidClientMac
	if err := server.Finish(ke3); err == nil || err.Error() != expected.Error() {
		t.Fatalf("expected error on invalid mac - got %v", err)
	}
}

// client.go

func TestClientRegistrationFinalize_InvalidPks(t *testing.T) {
	/*
		Empty and invalid server public key sent to client
	*/
	credID := utils.RandomBytes(32)
	oprfSeed := utils.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		_, pks := server.KeyGen()
		r1 := client.RegistrationInit([]byte("yo"))

		r2, err := server.RegistrationResponse(r1, pks, credID, oprfSeed)
		if err != nil {
			t.Fatal(err)
		}

		// nil pks
		r2.Pks = nil
		expected := "invalid server public key :"
		if _, _, err := client.RegistrationFinalize(nil, &opaque.Credentials{}, r2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid server public key - got %v", err)
		}

		// nil pks
		r2.Pks = getBadElement(t, conf)
		if _, _, err := client.RegistrationFinalize(nil, &opaque.Credentials{}, r2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid server public key - got %v", err)
		}
	}
}

func TestClientRegistrationFinalize_InvalidEvaluation(t *testing.T) {
	/*
		Oprf finalize - evaluation deserialization // element decoding
	*/
	for _, conf := range confs {
		client := conf.Conf.Client()
		badr2 := &message.RegistrationResponse{
			Data: getBadElement(t, conf),
			Pks:  client.AKEGroup.Get().Base().Bytes(),
		}

		expected := "building envelope: finalizing OPRF : "
		if _, _, err := client.RegistrationFinalize(nil, &opaque.Credentials{}, badr2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid evualuated element - got %v", err)
		}
	}
}

func TestClientFinish_BadEvaluation(t *testing.T) {
	/*
		Oprf finalize : evaluation deserialization // element decoding
	*/
	for _, conf := range confs {
		client := conf.Conf.Client()
		_ = client.Init([]byte("yo"))
		ke2 := &message.KE2{
			CredentialResponse: &message2.CredentialResponse{
				Data: getBadElement(t, conf),
			},
		}

		expected := "finalizing OPRF : could not decode element :"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid evaluated elemenet - got %v", err)
		}
	}
}

func TestClientFinish_BadMaskedResponse(t *testing.T) {
	/*
		The masked response is of invalid length.
	*/
	credID := utils.RandomBytes(32)
	oprfSeed := utils.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)

		goodLength := encoding.PointLength[client.AKEGroup] + client.EnvelopeSize
		expected := "invalid masked response length"

		// too short
		ke2.MaskedResponse = utils.RandomBytes(goodLength - 1)
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for short response - got %v", err)
		}

		// too long
		ke2.MaskedResponse = utils.RandomBytes(goodLength + 1)
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for long response - got %v", err)
		}
	}
}

func TestClientFinish_InvalidEnvelopeTag(t *testing.T) {
	/*
		Invalid envelope tag
	*/
	credID := utils.RandomBytes(32)
	oprfSeed := utils.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)

		env, _, err := getEnvelope(envelope.Mode(conf.Conf.Mode), client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		// tamper the envelope
		env.AuthTag = utils.RandomBytes(client.MAC.Size())
		clear := encoding.Concat(pks, env.Serialize())
		ke2.MaskedResponse = server.MaskResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		// too short
		expected := "recover envelope: invalid envelope authentication tag"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid envelope mac - got %v", err)
		}
	}
}

func TestClientFinish_InvalidKE2KeyEncoding(t *testing.T) {
	/*
		Invalid envelope tag
	*/
	credID := utils.RandomBytes(32)
	oprfSeed := utils.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)
		epks := ke2.EpkS

		// tamper epks
		ke2.EpkS = getBadElement(t, conf)
		expected := " AKE finalization: decoding peer ephemeral public key:"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}

		// tamper PKS
		ke2.EpkS = epks
		env, randomizedPwd, err := getEnvelope(envelope.Mode(conf.Conf.Mode), client, ke2)
		if err != nil {
			t.Fatal(err)
		}

		badpks := getBadElement(t, conf)

		ctc := envelope.CreateCleartextCredentials(rec.RegistrationUpload.PublicKey, badpks, nil, nil)
		authKey := client.KDF.Expand(randomizedPwd, encoding.SuffixString(env.Nonce, tag.AuthKey), client.KDF.Size())
		authTag := client.MAC.MAC(authKey, encoding.Concat3(env.Nonce, env.InnerEnvelope, ctc.Serialize()))
		env.AuthTag = authTag

		clear := encoding.Concat(badpks, env.Serialize())
		ke2.MaskedResponse = server.MaskResponse(rec.MaskingKey, ke2.MaskingNonce, clear)

		expected = " AKE finalization: decoding peer public key:"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}
	}
}

func TestClientFinish_InvalidKE2Mac(t *testing.T) {
	/*
		Invalid server ke2 mac
	*/
	credID := utils.RandomBytes(32)
	oprfSeed := utils.RandomBytes(32)

	for _, conf := range confs {
		client := conf.Conf.Client()
		server := conf.Conf.Server()
		sks, pks := server.KeyGen()
		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)

		ke1 := client.Init([]byte("yo"))
		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)

		ke2.Mac = utils.RandomBytes(client.MAC.Size())
		expected := " AKE finalization: invalid server mac"
		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
			t.Fatalf("expected error for invalid epks encoding - got %q", err)
		}
	}
}

/*
	Magic errors appear: points are not modified but can't suddenly be decoded once past the tested function
*/

//func TestServerInit_InvalidSecretKey(t *testing.T) {
//	/*
//		Invalid server secret key
//	*/
//	for _, conf := range confs {
//		server := conf.Conf.Server()
//		_, pk := server.KeyGen()
//		expected := "invalid server secret key: "
//
//		// todo: computation hangs on bad NIST scalars: are they too high?
//
//		if _, err := server.Init(nil, nil, getBadScalar(t, conf), pk, nil, nil); err == nil || !strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("expected error on bad secret key - got %s", err)
//		}
//	}
//}

//func TestClientExternalInvalidKey(t *testing.T) {
//	/*
//		External mode invalid secret key encoding
//	*/
//	credID := utils.RandomBytes(32)
//	oprfSeed := utils.RandomBytes(32)
//
//	for _, conf := range confs {
//		conf.Conf.Mode = opaque.External
//		client := conf.Conf.Client()
//		r1 := client.RegistrationInit([]byte("yo"))
//		server := conf.Conf.Server()
//		_, pks := server.KeyGen()
//		r2, err := conf.Conf.Server().RegistrationResponse(r1, pks, credID, oprfSeed)
//		if err != nil {
//			t.Fatal(err)
//		}
//
//		if dc, err := client.OprfCiphersuite.Group().Get().NewElement().Decode(r2.Data); err != nil {
//			log.Printf("Test %v / %v --- %v", client.OprfCiphersuite, r2.Data, err)
//		} else {
//			log.Printf("Test %v \n\t%v --- %v", client.OprfCiphersuite, dc.Bytes(), err)
//		}
//
//		expected := "building envelope: can't build envelope: invalid secret key encoding"
//		if _, _, err := client.RegistrationFinalize(getBadScalar(t, conf), &opaque.Credentials{}, r2); err == nil || !strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("expected error for invalid client secret key - got %v", err)
//		}
//	}
//}

//func TestClientFinish_ExternalInvalidSecretKey(t *testing.T) {
//	/*
//		The key recovered from the envelope is an invalid scalar in the external mode.
//	 */
//	credID := utils.RandomBytes(32)
//	oprfSeed := utils.RandomBytes(32)
//
//	for i, conf := range confs {
//		log.Printf("%d", i)
//		conf.Conf.Mode = opaque.External
//		client := conf.Conf.Client()
//		server := conf.Conf.Server()
//		sks, pks := server.KeyGen()
//		rec := buildRecord(t, credID, oprfSeed, []byte("yo"), pks, client, server)
//
//		ke1 := client.Init([]byte("yo"))
//		ke2, _ := server.Init(ke1, nil, sks, pks, oprfSeed, rec)
//		log.Printf("data %v", ke2.Data)
//
//		env, randomizedPwd, err := getEnvelope(envelope.Mode(conf.Conf.Mode), client, ke2)
//		if err != nil {
//			t.Fatal(err)
//		}
//
//		// tamper the envelope
//		badKey := getBadScalar(t, conf)
//		pad := client.KDF.Expand(randomizedPwd, encoding.SuffixString(env.Nonce, tag.Pad), len(badKey))
//		env.InnerEnvelope = internal.Xor(badKey, pad)
//		ctc := envelope.CreateCleartextCredentials(client.AKEGroup.Get().Base().Bytes(), pks, nil, nil)
//		authKey := client.KDF.Expand(randomizedPwd, encoding.SuffixString(env.Nonce, tag.AuthKey), client.KDF.Size())
//		authTag := client.MAC.MAC(authKey, encoding.Concat3(env.Nonce, env.InnerEnvelope, ctc.Serialize()))
//		env.AuthTag = authTag
//
//		clear := encoding.Concat(pks, env.Serialize())
//		ke2.MaskedResponse = server.MaskResponse(rec.MaskingKey, ke2.MaskingNonce, clear)
//
//		// too short
//		expected := "recover envelope: can't recover envelope: invalid secret key encoding"
//		if _, _, err := client.Finish(nil, nil, ke2); err == nil || !strings.HasPrefix(err.Error(), expected) {
//			t.Fatalf("%d expected error for short response - got %v", i, err)
//		}
//	}
//}
