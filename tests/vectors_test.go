package tests

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/opaque"

	"github.com/bytemare/opaque/internal/core/envelope"
	"github.com/bytemare/opaque/message"

	"github.com/bytemare/cryptotools/mhf"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/voprf"
)

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
	EnvelopeMode string    `json:"EnvelopeMode"`
	Group        string    `json:"Group"`
	Hash         string    `json:"Hash"`
	KDF          string    `json:"KDF"`
	MAC          string    `json:"MAC"`
	MHF          string    `json:"MHF"`
	Name         string    `json:"Name"`
	OPRF         ByteToHex `json:"OPRF"`
}

type inputs struct {
	BlindLogin            ByteToHex `json:"blind_login"`
	BlindRegistration     ByteToHex `json:"blind_registration"`
	ClientIdentity        ByteToHex `json:"client_identity,omitempty"`
	ClientInfo            ByteToHex `json:"client_info"`
	ClientKeyshare        ByteToHex `json:"client_keyshare"`
	ClientNonce           ByteToHex `json:"client_nonce"`
	ClientPrivateKey      ByteToHex `json:"client_private_key"`
	ClientPrivateKeyshare ByteToHex `json:"client_private_keyshare"`
	CredentialIdentifier  ByteToHex `json:"credential_identifier"`
	EnvelopeNonce         ByteToHex `json:"envelope_nonce"`
	MaskingNonce          ByteToHex `json:"masking_nonce"`
	OprfKey               ByteToHex `json:"oprf_key"`
	OprfSeed              ByteToHex `json:"oprf_seed"`
	Password              ByteToHex `json:"password"`
	ServerIdentity        ByteToHex `json:"server_identity,omitempty"`
	ServerInfo            ByteToHex `json:"server_info"`
	ServerKeyshare        ByteToHex `json:"server_keyshare"`
	ServerNonce           ByteToHex `json:"server_nonce"`
	ServerPrivateKey      ByteToHex `json:"server_private_key"`
	ServerPrivateKeyshare ByteToHex `json:"server_private_keyshare"`
	ServerPublicKey       ByteToHex `json:"server_public_key"`
}

type intermediates struct {
	AuthKey             ByteToHex `json:"auth_key"`       //
	ClientMacKey        ByteToHex `json:"client_mac_key"` //
	ClientPublicKey     ByteToHex `json:"client_public_key"`
	Envelope            ByteToHex `json:"envelope"`              //
	HandshakeEncryptKey ByteToHex `json:"handshake_encrypt_key"` //
	HandshakeSecret     ByteToHex `json:"handshake_secret"`      //
	MaskingKey          ByteToHex `json:"masking_key"`
	RandomPWD           ByteToHex `json:"randomized_pwd"` //
	ServerMacKey        ByteToHex `json:"server_mac_key"` //
}

type outputs struct {
	KE1                  ByteToHex `json:"KE1"`                   //
	KE2                  ByteToHex `json:"KE2"`                   //
	KE3                  ByteToHex `json:"KE3"`                   //
	ExportKey            ByteToHex `json:"export_key"`            //
	RegistrationRequest  ByteToHex `json:"registration_request"`  //
	RegistrationResponse ByteToHex `json:"registration_response"` //
	RegistrationUpload   ByteToHex `json:"registration_upload"`   //
	SessionKey           ByteToHex `json:"session_key"`           //
}

type vector struct {
	Config        config        `json:"config"`
	Inputs        inputs        `json:"inputs"`
	Intermediates intermediates `json:"intermediates"`
	Outputs       outputs       `json:"outputs"`
}

func (v *vector) test(t *testing.T) {
	mode, err := hex.DecodeString(v.Config.EnvelopeMode)
	if err != nil {
		t.Fatal(err)
	}

	p := &opaque.Parameters{
		OprfCiphersuite: voprf.Ciphersuite(v.Config.OPRF[1]),
		Hash:            hashToHash(v.Config.Hash),
		KDF:             kdfToHash(v.Config.KDF),
		MAC:             macToHash(v.Config.MAC),
		MHF:             mhf.Scrypt,
		Mode:            opaque.Mode(mode[0]),
		AKEGroup:        voprf.Ciphersuite(v.Config.OPRF[1]).Group(),
		NonceLen:        32,
	}

	// harden := tests.IdentityMHF

	input := v.Inputs
	check := v.Intermediates
	out := v.Outputs

	/*
		Registration
	*/

	// Client
	client := p.Client()
	oprfClient := buildOPRFClient(p.OprfCiphersuite, input.BlindRegistration)
	client.Core.Oprf = oprfClient
	regReq := client.RegistrationInit(input.Password)

	if !bytes.Equal(out.RegistrationRequest, regReq.Serialize()) {
		t.Fatal("registration requests do not match")
	}

	// Server
	server := p.Server()
	regResp, ku, err := server.RegistrationResponse(regReq, input.ServerPublicKey, opaque.CredentialIdentifier(input.CredentialIdentifier), input.OprfSeed)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(input.OprfKey, ku) {
		t.Fatal("oprf keys do not match")
	}

	vRegResp, err := client.DeserializeRegistrationResponse(out.RegistrationResponse)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(vRegResp.Data, regResp.Data) {
		t.Fatal("registration response data do not match")
	}

	if !bytes.Equal(vRegResp.Pks, regResp.Pks) {
		t.Fatal("registration response pks do not match")
	}

	if !bytes.Equal(out.RegistrationResponse, regResp.Serialize()) {
		t.Fatal("registration responses do not match")
	}

	// Client
	clientCredentials := &envelope.Credentials{
		Idc:           input.ClientIdentity,
		Ids:           input.ServerIdentity,
		EnvelopeNonce: input.EnvelopeNonce,
	}

	upload, exportKey, err := client.RegistrationFinalize(input.ClientPrivateKey, clientCredentials, regResp)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out.ExportKey, exportKey) {
		t.Fatal("exportKey do not match")
	}

	//if !bytes.Equal(check.ClientPublicKey, upload.PublicKey) {
	//	t.Fatal("Client PublicKey do not match")
	//}

	if !bytes.Equal(check.Envelope, upload.Envelope) {
		t.Fatalf("envelopes do not match\nexpected %v,\nngot %v", check.Envelope, upload.Envelope)
	}

	if !bytes.Equal(out.RegistrationUpload, upload.Serialize()) {
		t.Fatalf("registration upload do not match")
	}

	/*
		Login
	*/

	// Client
	client = p.Client()
	client.Core.Oprf = buildOPRFClient(p.OprfCiphersuite, input.BlindLogin)
	esk, err := client.Ake.Group.NewScalar().Decode(input.ClientPrivateKeyshare)
	if err != nil {
		t.Fatal(err)
	}
	client.Ake.Initialize(esk, input.ClientNonce, 32)
	KE1 := client.AuthenticationInit(input.Password, input.ClientInfo)

	if !bytes.Equal(out.KE1, KE1.Serialize()) {
		t.Fatal("KE1 do not match")
	}

	// Server
	server = p.Server()

	serverCredentials := &envelope.Credentials{
		Idc:          input.ClientIdentity,
		Ids:          input.ServerIdentity,
		MaskingNonce: input.MaskingNonce,
	}

	cupload, err := client.DeserializeRegistrationUpload(out.RegistrationUpload)
	if err != nil {
		t.Fatal(err)
	}

	_ = v.loginResponse(t, server, KE1, serverCredentials, cupload, opaque.CredentialIdentifier(input.CredentialIdentifier), input.OprfSeed, input.ServerPrivateKey, input.ServerPublicKey)

	// Client
	cke2, err := client.DeserializeKE2(out.KE2)
	if err != nil {
		t.Fatal(err)
	}

	ke3, exportKey, err := client.AuthenticationFinalize(input.ClientIdentity, input.ServerIdentity, cke2)
	if err != nil {
		t.Fatal(err)
	}

	//if !bytes.Equal(v.Intermediates.ClientMacKey, client.Ake.ClientMacKey) {
	//	t.Fatal("client mac keys do not match")
	//}

	if !bytes.Equal(v.Outputs.ExportKey, exportKey) {
		t.Fatal("Client export keys do not match")
	}

	if !bytes.Equal(v.Outputs.SessionKey, client.SessionKey()) {
		t.Fatal("Client session keys do not match")
	}

	if !bytes.Equal(v.Outputs.KE3, ke3.Serialize()) {
		t.Fatal("KE3 do not match")
	}

	if err := server.AuthenticationFinalize(ke3); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.Outputs.SessionKey, server.SessionKey()) {
		t.Fatal("Server session keys do not match")
	}
}

func (v *vector) loginResponse(t *testing.T, s *opaque.Server, ke1 *message.KE1, creds *envelope.Credentials, upload *message.RegistrationUpload, id opaque.CredentialIdentifier, oprfSeed, serverPrivateKey, serverPublicKey []byte) *message.KE2 {
	sks, err := s.Ake.Group.NewScalar().Decode(v.Inputs.ServerPrivateKeyshare)
	if err != nil {
		t.Fatal(err)
	}
	s.Ake.Initialize(sks, v.Inputs.ServerNonce, 32)

	KE2, err := s.AuthenticationInit(ke1, v.Inputs.ServerInfo, serverPrivateKey, serverPublicKey, upload, creds, id, oprfSeed)
	if err != nil {
		t.Fatal(err)
	}

	//if !bytes.Equal(v.Intermediates.HandshakeSecret, s.Ake.HandshakeSecret) {
	//	t.Fatalf("HandshakeSecrets do not match : %v", s.Ake.HandshakeSecret)
	//}

	//if !bytes.Equal(v.Intermediates.ServerMacKey, s.Ake.ServerMacKey) {
	//	t.Fatalf("ServerMacs do not match.expected %v,\ngot %v", v.Intermediates.ServerMacKey, s.Ake.ServerMacKey)
	//}

	//if !bytes.Equal(v.Intermediates.ClientMacKey, s.Ake.Keys.ClientMacKey) {
	//	t.Fatal("ClientMacs do not match")
	//}

	//if !bytes.Equal(v.Intermediates.HandshakeEncryptKey, s.Ake.HandshakeEncryptKey) {
	//	t.Fatal("HandshakeEncryptKeys do not match")
	//}

	if !bytes.Equal(v.Outputs.SessionKey, s.Ake.SessionSecret) {
		t.Fatalf("SessionKey do not match : %v", s.Ake.SessionKey())
	}

	draftKE2, err := s.DeserializeKE2(v.Outputs.KE2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(draftKE2.CredentialResponse.Serialize(), KE2.CredentialResponse.Serialize()) {
		t.Fatal("CredResp do not match")
	}

	if !bytes.Equal(draftKE2.CredentialResponse.Data, KE2.CredentialResponse.Data) {
		t.Fatal("data do not match")
	}

	if !bytes.Equal(draftKE2.CredentialResponse.MaskingNonce, KE2.CredentialResponse.MaskingNonce) {
		t.Fatal("pks do not match")
	}

	if !bytes.Equal(draftKE2.CredentialResponse.MaskedResponse, KE2.CredentialResponse.MaskedResponse) {
		t.Fatal("envu do not match")
	}

	if !bytes.Equal(draftKE2.NonceS, KE2.NonceS) {
		t.Fatal("nonces do not match")
	}

	if !bytes.Equal(draftKE2.EpkS, KE2.EpkS) {
		t.Fatal("epks do not match")
	}

	if !bytes.Equal(draftKE2.Einfo, KE2.Einfo) {
		t.Fatalf("einfo do not match")
	}

	if !bytes.Equal(draftKE2.Mac, KE2.Mac) {
		t.Fatal("server macs do not match")
	}

	if !bytes.Equal(v.Outputs.KE2, KE2.Serialize()) {
		t.Fatal("KE2 do not match")
	}

	return KE2
}

func buildOPRFClient(cs voprf.Ciphersuite, blind []byte) *voprf.Client {
	s := voprf.State{
		Ciphersuite: cs,
		Mode:        voprf.Base,
		Blinding:    voprf.Multiplicative,
		Blind:       make([][]byte, 1),
	}
	s.Blind[0] = blind

	c, err := cs.Client(nil)
	if err != nil {
		panic(err)
	}

	if err = c.Import(&s); err != nil {
		panic(err)
	}

	return c
}

func hashToHash(h string) hash.Hashing {
	switch h {
	case "SHA256":
		return hash.SHA256
	case "SHA512":
		return hash.SHA512
	default:
		return 0
	}
}

func kdfToHash(h string) hash.Hashing {
	switch h {
	case "HKDF-SHA256":
		return hash.SHA256
	case "HKDF-SHA512":
		return hash.SHA512
	default:
		return 0
	}
}

func macToHash(h string) hash.Hashing {
	switch h {
	case "HMAC-SHA256":
		return hash.SHA256
	case "HMAC-SHA512":
		return hash.SHA512
	default:
		return 0
	}
}

type draftVectors []*vector

func TestOpaqueVectors(t *testing.T) {
	if err := filepath.Walk("vectors.json",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var v draftVectors
			errJSON := json.Unmarshal(contents, &v)
			if errJSON != nil {
				return errJSON
			}

			for _, tv := range v {

				// Decaf448 not supported, yet
				if tv.Config.Group == "decaf448" {
					continue
				}

				t.Run(fmt.Sprintf("%s - %s - %s", tv.Config.Name, tv.Config.EnvelopeMode, tv.Config.Group), tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}
