package opaque

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/bytemare/opaque/internal/oprf"

	"github.com/bytemare/crypto/hash"
	"github.com/bytemare/crypto/ksf"

	"github.com/bytemare/opaque"
)

func fuzzTestConfigurationError(t *testing.T, c *opaque.Configuration, err error) {
	// Errors tested for
	var (
		errInvalidKDFid  = errors.New("invalid KDF id")
		errInvalidMACid  = errors.New("invalid MAC id")
		errInvalidHASHid = errors.New("invalid Hash id")
		errInvalidKSFid  = errors.New("invalid KSF id")
		errInvalidOPRFid = errors.New("invalid OPRF group id")
		errInvalidAKEid  = errors.New("invalid AKE group id")
	)

	if strings.Contains(err.Error(), errInvalidKDFid.Error()) {
		if hash.Hashing(c.KDF).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidKDFid, c.KDF)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidMACid.Error()) {
		if hash.Hashing(c.MAC).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidMACid, c.MAC)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidHASHid.Error()) {
		if hash.Hashing(c.Hash).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidHASHid, c.Hash)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidKSFid.Error()) {
		if c.KSF.Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidKSFid, c.KSF)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidOPRFid.Error()) {
		if oprf.Ciphersuite(c.OPRF).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidOPRFid, c.OPRF)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidAKEid.Error()) {
		if oprf.Ciphersuite(c.AKE).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidAKEid, c.AKE)
		}
		t.Skip()
	}

	t.Fatalf("Unrecognized error: %q", err)
}

func fuzzClientConfiguration(t *testing.T, c *opaque.Configuration) *opaque.Client {
	client, err := c.Client()
	if err != nil {
		fuzzTestConfigurationError(t, c, err)
	}
	if client == nil {
		t.Fatal("server is nil")
	}

	return client
}

func fuzzServerConfiguration(t *testing.T, c *opaque.Configuration) *opaque.Server {
	server, err := c.Server()
	if err != nil {
		fuzzTestConfigurationError(t, c, err)
	}
	if server == nil {
		t.Fatal("server is nil")
	}

	return server
}

type ByteToHex []byte

func (j ByteToHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(j))
}

func (j *ByteToHex) UnmarshalJSON(b []byte) error {
	bs := strings.Trim(string(b), "\"")

	dst, err := hex.DecodeString(bs)
	if err != nil {
		return err
	}

	*j = dst
	return nil
}

/*
	Test test vectors
*/

type config struct {
	Context ByteToHex `json:"Context"`
	// EnvelopeMode string    `json:"EnvelopeMode"`
	Fake  string    `json:"Fake"`
	Group string    `json:"Group"`
	Hash  string    `json:"Hash"`
	KDF   string    `json:"KDF"`
	MAC   string    `json:"MAC"`
	KSF   string    `json:"KSF"`
	Name  string    `json:"Name"`
	OPRF  ByteToHex `json:"OPRF"`
}

type inputs struct {
	BlindLogin            ByteToHex `json:"blind_login"`
	BlindRegistration     ByteToHex `json:"blind_registration"`
	ClientIdentity        ByteToHex `json:"client_identity,omitempty"`
	Context               ByteToHex `json:"context"`
	ClientKeyshare        ByteToHex `json:"client_keyshare"`
	ClientNonce           ByteToHex `json:"client_nonce"`
	ClientPrivateKeyshare ByteToHex `json:"client_private_keyshare"`
	CredentialIdentifier  ByteToHex `json:"credential_identifier"`
	EnvelopeNonce         ByteToHex `json:"envelope_nonce"`
	MaskingNonce          ByteToHex `json:"masking_nonce"`
	OprfKey               ByteToHex `json:"oprf_key"`
	OprfSeed              ByteToHex `json:"oprf_seed"`
	Password              ByteToHex `json:"password"`
	ServerIdentity        ByteToHex `json:"server_identity,omitempty"`
	ServerKeyshare        ByteToHex `json:"server_keyshare"`
	ServerNonce           ByteToHex `json:"server_nonce"`
	ServerPrivateKey      ByteToHex `json:"server_private_key"`
	ServerPrivateKeyshare ByteToHex `json:"server_private_keyshare"`
	ServerPublicKey       ByteToHex `json:"server_public_key"`
	KE1                   ByteToHex `json:"KE1"`               // Used for fake credentials tests
	ClientPublicKey       ByteToHex `json:"client_public_key"` // Used for fake credentials tests
	MaskingKey            ByteToHex `json:"masking_key"`       // Used for fake credentials tests
}

type intermediates struct {
	AuthKey         ByteToHex `json:"auth_key"`       //
	ClientMacKey    ByteToHex `json:"client_mac_key"` //
	ClientPublicKey ByteToHex `json:"client_public_key"`
	Envelope        ByteToHex `json:"envelope"`         //
	HandshakeSecret ByteToHex `json:"handshake_secret"` //
	MaskingKey      ByteToHex `json:"masking_key"`
	RandomPWD       ByteToHex `json:"randomized_pwd"` //
	ServerMacKey    ByteToHex `json:"server_mac_key"` //
}

type outputs struct {
	KE1                  ByteToHex `json:"KE1"`                   //
	KE2                  ByteToHex `json:"KE2"`                   //
	KE3                  ByteToHex `json:"KE3"`                   //
	ExportKey            ByteToHex `json:"export_key"`            //
	RegistrationRequest  ByteToHex `json:"registration_request"`  //
	RegistrationResponse ByteToHex `json:"registration_response"` //
	RegistrationRecord   ByteToHex `json:"registration_upload"`   //
	SessionKey           ByteToHex `json:"session_key"`           //
}

type vector struct {
	Config        config        `json:"config"`
	Inputs        inputs        `json:"inputs"`
	Intermediates intermediates `json:"intermediates"`
	Outputs       outputs       `json:"outputs"`
}

func fuzzLoadVectors(path string) ([]*vector, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no vectors to read: %v", err)
	}

	var v []*vector
	err = json.Unmarshal(contents, &v)
	if err != nil {
		return nil, fmt.Errorf("no vectors to read: %v", err)
	}

	return v, nil
}

func hashToHash(h string) crypto.Hash {
	switch h {
	case "SHA256":
		return crypto.SHA256
	case "SHA512":
		return crypto.SHA512
	default:
		return 0
	}
}

func kdfToHash(h string) crypto.Hash {
	switch h {
	case "HKDF-SHA256":
		return crypto.SHA256
	case "HKDF-SHA512":
		return crypto.SHA512
	default:
		return 0
	}
}

func macToHash(h string) crypto.Hash {
	switch h {
	case "HMAC-SHA256":
		return crypto.SHA256
	case "HMAC-SHA512":
		return crypto.SHA512
	default:
		return 0
	}
}

func ksfToKSF(h string) ksf.Identifier {
	switch h {
	case "Identity":
		return 0
	case "Scrypt":
		return ksf.Scrypt
	default:
		return 0
	}
}

func groupToGroup(g string) opaque.Group {
	switch g {
	case "ristretto255":
		return opaque.RistrettoSha512
	case "decaf448":
		panic("group not supported")
	case "P256_XMD:SHA-256_SSWU_RO_":
		return opaque.P256Sha256
	case "P384_XMD:SHA-384_SSWU_RO_":
		return opaque.P384Sha512
	case "P521_XMD:SHA-512_SSWU_RO_":
		return opaque.P521Sha512
	// case "curve25519_XMD:SHA-512_ELL2_RO_":
	//	return opaque.Curve25519Sha512
	default:
		panic("group not recognised")
	}
}

func FuzzConfiguration(f *testing.F) {
	// seed corpus
	vectors, err := fuzzLoadVectors("../vectors.json")
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range vectors {
		f.Add([]byte(v.Outputs.KE1),
			[]byte(v.Config.Context),
			uint(kdfToHash(v.Config.KDF)),
			uint(macToHash(v.Config.MAC)),
			uint(hashToHash(v.Config.Hash)),
			v.Config.OPRF[1],
			byte(ksfToKSF(v.Config.KSF)),
			byte(groupToGroup(v.Config.Group)),
		)
	}

	// previous crashers
	f.Add([]byte("0"), []byte(""), uint(7), uint(37), uint(7), byte('\x05'), byte('\x02'), byte('\x05'))
	f.Add([]byte("0"), []byte("0"), uint(13), uint(5), uint(5), byte('\x03'), byte('\r'), byte('\x03'))
	f.Add([]byte("0"), []byte("0"), uint(13), uint(5), uint(5), byte('\a'), byte('\x04'), byte('\x03'))

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := &opaque.Configuration{
			Context: context,
			KDF:     crypto.Hash(kdf),
			MAC:     crypto.Hash(mac),
			Hash:    crypto.Hash(h),
			OPRF:    opaque.Group(oprf),
			KSF:     ksf.Identifier(_ksf),
			AKE:     opaque.Group(ake),
		}
		_ = fuzzServerConfiguration(t, c)
		_ = fuzzClientConfiguration(t, c)
	})
}

func loadVectorSeedCorpus(f *testing.F, stage string) {
	// seed corpus
	vectors, err := fuzzLoadVectors("../vectors.json")
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range vectors {
		var input ByteToHex
		switch stage {
		case "RegistrationRequest":
			input = v.Outputs.RegistrationRequest
		case "RegistrationResponse":
			input = v.Outputs.RegistrationResponse
		case "RegistrationRecord":
			input = v.Outputs.RegistrationRecord
		case "KE1":
			input = v.Outputs.KE1
		case "KE2":
			input = v.Outputs.KE2
		case "KE3":
			input = v.Outputs.KE3
		default:
			panic(nil)
		}

		f.Add([]byte(input),
			[]byte(v.Config.Context),
			uint(kdfToHash(v.Config.KDF)),
			uint(macToHash(v.Config.MAC)),
			uint(hashToHash(v.Config.Hash)),
			v.Config.OPRF[1],
			byte(ksfToKSF(v.Config.KSF)),
			byte(groupToGroup(v.Config.Group)),
		)
	}

	// previous crashers
	f.Add([]byte("0"), []byte(""), uint(7), uint(37), uint(7), byte('\x05'), byte('\x02'), byte('\x05'))
	f.Add([]byte("0"), []byte("0"), uint(13), uint(5), uint(5), byte('\x03'), byte('\r'), byte('\x03'))
	f.Add([]byte("0"), []byte("0"), uint(13), uint(5), uint(5), byte('\a'), byte('\x04'), byte('\x03'))
	f.Add([]byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), []byte("0"), uint(7), uint(7), uint(7), byte('\x01'), byte('\x03'), byte('\x01'))
}

func inputToConfig(context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) *opaque.Configuration {
	return &opaque.Configuration{
		Context: context,
		KDF:     crypto.Hash(kdf),
		MAC:     crypto.Hash(mac),
		Hash:    crypto.Hash(h),
		OPRF:    opaque.Group(oprf),
		KSF:     ksf.Identifier(_ksf),
		AKE:     opaque.Group(ake),
	}
}

func FuzzDeserializeRegistrationRequest(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidBlindedData   = errors.New("blinded data is an invalid point")
	)

	loadVectorSeedCorpus(f, "RegistrationRequest")

	f.Fuzz(func(t *testing.T, r1, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		_, err = server.DeserializeRegistrationRequest(r1)
		if err != nil {
			conf := server.Parameters
			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(r1) == conf.OPRFPointLength {
				t.Fatalf("got %q but input length is valid", errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidBlindedData.Error()) {
				e, _err := conf.Group.NewElement().Decode(r1[:conf.OPRFPointLength])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but point is valid", errInvalidBlindedData)
				}
			}
		}
	})
}

func FuzzDeserializeRegistrationResponse(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
		errInvalidServerPK      = errors.New("invalid server public key")
	)

	loadVectorSeedCorpus(f, "RegistrationResponse")

	f.Fuzz(func(t *testing.T, r2, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
		client, err := c.Client()
		if err != nil {
			t.Skip()
		}

		_, err = client.DeserializeRegistrationResponse(r2)
		if err != nil {
			conf := client.Parameters
			maxResponseLength := conf.OPRFPointLength + conf.AkePointLength

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(r2) == maxResponseLength+conf.AkePointLength {
				t.Fatalf("got %q but input is valid", errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidEvaluatedData.Error()) {
				e, _err := conf.Group.NewElement().Decode(r2[:conf.OPRFPointLength])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but input is valid", errInvalidEvaluatedData)
				}
			}

			if strings.Contains(err.Error(), errInvalidServerPK.Error()) {
				e, _err := conf.Group.NewElement().Decode(r2[conf.OPRFPointLength:])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but input is valid", errInvalidServerPK)
				}
			}
		}
	})
}

func FuzzDeserializeRegistrationRecord(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidClientPK      = errors.New("invalid client public key")
	)

	loadVectorSeedCorpus(f, "RegistrationRecord")

	f.Fuzz(func(t *testing.T, r3, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		conf := server.Parameters

		_, err = server.DeserializeRegistrationRecord(r3)
		if err != nil {
			maxMessageLength := conf.AkePointLength + conf.Hash.Size() + conf.EnvelopeSize

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(r3) == maxMessageLength {
				t.Fatalf("got %q but input is valid", errInvalidMessageLength)
			}
		}

		if strings.Contains(err.Error(), errInvalidClientPK.Error()) {
			e, _err := conf.Group.NewElement().Decode(r3[:conf.AkePointLength])
			if _err == nil && !e.IsIdentity() {
				t.Fatalf("got %q but input is valid", errInvalidClientPK)
			}
		}
	})
}

func FuzzDeserializeKE1(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidBlindedData   = errors.New("blinded data is an invalid point")
		errInvalidClientEPK     = errors.New("invalid ephemeral client public key")
	)

	loadVectorSeedCorpus(f, "KE1")

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		_, err = server.DeserializeKE1(ke1)
		if err != nil {
			conf := server.Parameters
			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(ke1) == conf.OPRFPointLength+conf.NonceLen+conf.AkePointLength {
				t.Fatalf("got %q but input length is valid", errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidBlindedData.Error()) {
				e, _err := conf.Group.NewElement().Decode(ke1[:conf.OPRFPointLength])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but point is valid", errInvalidBlindedData)
				}
			}

			if strings.Contains(err.Error(), errInvalidClientEPK.Error()) {
				e, _err := conf.Group.NewElement().Decode(ke1[conf.OPRFPointLength+conf.NonceLen:])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but point is valid", errInvalidClientEPK)
				}
			}
		}
	})
}

func FuzzDeserializeKE2(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
		errInvalidServerEPK     = errors.New("invalid ephemeral server public key")
	)

	loadVectorSeedCorpus(f, "KE2")

	f.Fuzz(func(t *testing.T, ke2, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
		client, err := c.Client()
		if err != nil {
			t.Skip()
		}

		_, err = client.DeserializeKE2(ke2)
		if err != nil {
			conf := client.Parameters
			maxResponseLength := conf.OPRFPointLength + conf.NonceLen + conf.AkePointLength + conf.EnvelopeSize

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(ke2) == maxResponseLength+conf.NonceLen+conf.AkePointLength+conf.MAC.Size() {
				t.Fatalf("got %q but input is valid", errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidEvaluatedData.Error()) {
				e, _err := conf.Group.NewElement().Decode(ke2[:conf.OPRFPointLength])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but input is valid", errInvalidEvaluatedData)
				}
			}

			if strings.Contains(err.Error(), errInvalidServerEPK.Error()) {
				e, _err := conf.Group.NewElement().Decode(ke2[conf.OPRFPointLength+conf.NonceLen:])
				if _err == nil && !e.IsIdentity() {
					t.Fatalf("got %q but input is valid", errInvalidServerEPK)
				}
			}
		}
	})
}

func FuzzDeserializeKE3(f *testing.F) {
	// Error tested for
	errInvalidMessageLength := errors.New("invalid message length for the configuration")

	loadVectorSeedCorpus(f, "KE3")

	f.Fuzz(func(t *testing.T, ke3, context []byte, kdf, mac, h uint, oprf, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		_, err = server.DeserializeKE3(ke3)
		if err != nil {
			conf := server.Parameters
			maxMessageLength := conf.MAC.Size()

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(ke3) == maxMessageLength {
				t.Fatalf("got %q but input is valid", errInvalidMessageLength)
			}
		}
	})
}

//func FuzzRegistrationResponse(f *testing.F) {
//	// seed corpus
//	corpus := []string{
//		"c021ab3bca8c7c7949f7090d2af149523c5029d6c5c45b59997f8c306ccbdf75400ceac0fbfb16005928335518be6f930a113c6c0814521262e17ecc3cdc9f91da25553da9ac142b36332dbd487713ae6712432fb317a6e00b2b17525bbe6912",
//		"7002a52fa6c2916c49c1fff952e818e458c7f7799139b243918c97758f463a47e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421b1d63d7a2cfd90961b35150da8824e44af3cdc7a29880ff532751b7ccc6a8875ac14e08964942473de9484f7b",
//		"0226bc3aeccce9c813eaec852599fe76eafe611467a054e738441d4a3b7922aaba72721898ef81cc0a76a0b5508f2f7bb817e86f1dd05ca013190a68602c7af25f03a51c7c3d3a69f5217c0f8de4efa242b0cf4ba35cc67c820e57b69e7a4f53cd69",
//		"03ff69ee0b845955eafc817acf721fdecccc94977c4aa0841ec33bf5060375e3a4a2912bab9b6a62cddf7d5e3209a2859e5947586f69259e0708bdfab794f689ee038744dec9da18441e1ef78ff9b2e5d62c713e56eee7aa326a9be577365f919d6c",
//		"943a149cf304878367fa2dce5cb30eac23cfd1358e5cc0efdbd4361a9e7bd72dc26fead2a8b3d5910e25fd29402530b5c7e852585f843f3b939993624b8a7c3b581062b0e8e90db4798adbb49581f016034e0855b6d6199aceb56a71c9bd4866",
//		"0258384d63ae4bbddde6d00d41b0e7174695ff6234563e16fc284aa589c7de93f9b8bb2700cdd47e339d95404519f2fb3da58c93d84cbb4d51de6757a31919382b02630e46a94b7f8f66071d24794c37f605055c098afc04d637caf9b1bc714bd15c",
//	}
//
//	for _, s := range corpus {
//		b, err := hex.DecodeString(s)
//		if err != nil {
//			f.Fatal(err)
//		}
//		f.Add(b)
//	}
//
//	f.Fuzz(func(t *testing.T, ke1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed, record, credID, idc []byte) {
//		server := opaque.DefaultConfiguration().Server()
//		dKE1, err := server.DeserializeKE1(ke1)
//		if err != nil {
//			t.Fatalf("deserializing KE1: %v", err)
//		}
//
//		dRecord, err := server.DeserializeRegistrationRecord(record)
//		if err != nil {
//			t.Fatalf("deserializing record: %v", err)
//		}
//
//		cred := &opaque.ClientRecord{
//			CredentialIdentifier: credID,
//			ClientIdentity:       idc,
//			RegistrationRecord:   dRecord,
//			TestMaskNonce:        nil,
//		}
//
//		_, err = server.LoginInit(dKE1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed, cred)
//		if err != nil {
//			t.Fatalf("login: %v", err)
//		}
//	})
//}
