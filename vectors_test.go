package opaque

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bytemare/opaque/message"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/voprf"
)

var (
	OprfSuites = []voprf.Ciphersuite{voprf.RistrettoSha512, voprf.P256Sha256}
	Hashes     = []hash.Hashing{hash.SHA256, hash.SHA512}
	MHF        = []mhf.MHF{mhf.Argon2id}
	Modes      = []envelope.Mode{envelope.Base, envelope.CustomIdentifier}
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

type testEnvParameters struct {
	OPRFSuiteID  string `json:"OPRFSuite"`
	EnvHash      string `json:"EnvHash"`
	MHF          string `json:"MHF"`
	EnvelopeMode byte   `json:"EnvelopeMode"`
}

type testAkeParameters struct {
	AkeGroup          string `json:"AkeGroup"`
	AkeHash           string `json:"AkeHash"`
	SigmaSignatureAlg string `json:"SigmaSignatureAlg,omitempty"`
}

type testParameters struct {
	testEnvParameters `json:"Envelope"`
	testAkeParameters `json:"AKE"`
}

type testRegistrationInput struct {
	BlindReg ByteToHex `json:"RegistrationBlind"`
}

type testLoginInput struct {
	BlindLog           ByteToHex `json:"LoginBlind"`
	ClientAkePubkey    ByteToHex `json:"ClientAkePubkey"`
	ClientAkeSecretKey ByteToHex `json:"ClientAkeSecretKey"`
	ServerAkePubkey    ByteToHex `json:"ServerAkePubkey"`
	ServerAkeSecretKey ByteToHex `json:"ServerAkeSecretKey"`
	ClientEphPubkey    ByteToHex `json:"ClientEphPubkey"`
	ClientEphSecretKey ByteToHex `json:"ClientEphSecretKey"`
	ServerEphPubkey    ByteToHex `json:"ServerEphPubkey"`
	ServerEphSecretKey ByteToHex `json:"ServerEphSecretKey"`
	ClientNonce        ByteToHex `json:"ClientNonce"`
	ServerNonce        ByteToHex `json:"ServerNonce"`
	Info1              ByteToHex `json:"Info1"`
	Info2              ByteToHex `json:"Info2"`
}

type testInput struct {
	Idu                   ByteToHex `json:"Idu"`
	Ids                   ByteToHex `json:"Ids"`
	Password              ByteToHex `json:"Password"`
	OprfKey               ByteToHex `json:"OprfKey"`
	EnvelopeNonce         ByteToHex `json:"EnvelopeNonce"`
	testRegistrationInput `json:"Registration"`
	testLoginInput        `json:"Login"`
}

type testMessages struct {
	RegistrationRequest  ByteToHex `json:"RegistrationRequest"`
	RegistrationResponse ByteToHex `json:"RegistrationResponse"`
	RegistrationUpload   ByteToHex `json:"RegistrationUpload"`
	CredentialRequest    ByteToHex `json:"CredentialRequest"`
	CredentialResponse   ByteToHex `json:"CredentialResponse"`
	KeyExchange          ByteToHex `json:"KeyExchange"`
}

type testOutput struct {
	testMessages   `json:"Messages"`
	EInfo          ByteToHex      `json:"EInfo"`
	Envelope       ByteToHex      `json:"Envelope"`
	CredentialFile CredentialFile `json:"CredentialFile"`
	ExportKey      ByteToHex      `json:"ExportKey"`
	SharedSecret   ByteToHex      `json:"SharedSecret"`
}

type testVector struct {
	testParameters `json:"Parameters"`
	testInput      `json:"Input"`
	testOutput     `json:"Output"`
}

func GenerateTestVector(p *Parameters, m *mhf.Parameters, s signature.Identifier) *testVector {
	params := testParameters{
		testEnvParameters: testEnvParameters{
			OPRFSuiteID:  p.OprfCiphersuite.String(),
			EnvHash:      p.Hash.String(),
			MHF:          m.String(),
			EnvelopeMode: byte(p.Mode),
		},
		testAkeParameters: testAkeParameters{
			AkeGroup:          p.OprfCiphersuite.String(),
			AkeHash:           p.Hash.String(),
			SigmaSignatureAlg: s.String(),
		},
	}

	in := testInput{
		Idu:                   []byte("client"),
		Ids:                   []byte("server"),
		Password:              utils.RandomBytes(8),
		OprfKey:               nil,
		EnvelopeNonce:         nil,
		testRegistrationInput: testRegistrationInput{},
		testLoginInput: testLoginInput{
			Info1: []byte("aa"),
			Info2: []byte("aaa"),
		},
	}

	out := testOutput{
		testMessages:   testMessages{},
		Envelope:       nil,
		CredentialFile: CredentialFile{},
		ExportKey:      nil,
		SharedSecret:   nil,
	}

	/*
		Registration
	*/

	// Client
	client := p.Client(m)
	reqReg := client.RegistrationStart(in.Password)
	in.BlindReg = client.Core.Oprf.Export().Blind[0]

	out.RegistrationRequest = reqReg.Serialize()

	in.ClientAkeSecretKey, in.ClientAkePubkey = client.KeyGen()

	// Server
	serverOprfKeys := p.OprfCiphersuite.KeyGen()
	in.OprfKey = serverOprfKeys.SecretKey
	server := p.Server()
	in.ServerAkeSecretKey, in.ServerAkePubkey = server.KeyGen()

	respReg, _, err := server.RegistrationResponse(reqReg, in.ServerAkePubkey, in.OprfKey)
	if err != nil {
		panic(err)
	}

	out.RegistrationResponse = respReg.Serialize()

	creds := &envelope.Credentials{
		Sk:    in.ClientAkeSecretKey,
		Pk:    in.ClientAkePubkey,
		Idu:   in.Idu,
		Ids:   in.Ids,
		Nonce: utils.RandomBytes(32),
	}

	// Client
	upload, _, err := client.RegistrationFinalize(creds, respReg)
	if err != nil {
		panic(err)
	}

	out.RegistrationUpload = upload.Serialize()
	in.EnvelopeNonce = upload.Envelope.Contents.Nonce
	out.Envelope = upload.Envelope.Serialize()

	file := &CredentialFile{
		Ku:       in.OprfKey,
		Pku:      upload.Pku,
		Envelope: upload.Envelope,
	}

	out.CredentialFile = *file

	/*
		Authentication
	*/

	// Client
	client = p.Client(m)
	reqCreds := client.AuthenticationStart(in.Password, nil)

	in.BlindLog = client.Core.Oprf.Export().Blind[0]
	in.ClientEphPubkey = client.Ake.Epk.Bytes()
	in.ClientEphSecretKey = client.Ake.Esk.Bytes()
	in.ClientNonce = client.Ake.NonceU

	reqc := reqCreds.Serialize()
	out.CredentialRequest = reqc

	// Server
	server = p.Server()
	serverCreds := &envelope.Credentials{
		Sk:  in.ServerAkeSecretKey,
		Pk:  in.ServerAkePubkey,
		Idu: in.Idu,
		Ids: in.Ids,
	}
	respCreds, err := server.AuthenticationResponse(reqCreds, nil, &out.CredentialFile, serverCreds)
	if err != nil {
		panic(err)
	}

	in.ServerEphPubkey = server.Ake.Epk.Bytes()
	in.ServerEphSecretKey = server.Ake.Esk.Bytes()
	in.ServerNonce = server.Ake.NonceS

	respc := respCreds.Serialize()
	out.CredentialResponse = respc

	// Client
	fin, exportKey, err := client.AuthenticationFinalize(in.Idu, in.Ids, respCreds)
	if err != nil {
		panic(err)
	}

	finc := fin.Serialize()
	out.KeyExchange = finc

	out.ExportKey = exportKey

	if !bytes.Equal(client.SessionKey(), server.SessionKey()) {
		panic("Session secrets don't match.")
	}

	out.SharedSecret = client.SessionKey()

	return &testVector{
		testParameters: params,
		testInput:      in,
		testOutput:     out,
	}
}

func GenerateAllVectors(t *testing.T) []*testVector {
	v := len(OprfSuites) * len(Hashes) * len(MHF) * len(Modes)
	log.Printf("v := %v", v)
	vectors := make([]*testVector, v)
	w := 0
	for _, s := range OprfSuites {
		for _, h := range Hashes {
			for _, m := range MHF {
				for _, mode := range Modes {
					name := fmt.Sprintf("%d : %v-%v-%v-%v-%v", w, s, h, "3DH", m, mode)

					p := &Parameters{
						OprfCiphersuite: s,
						Mode:            mode,
						Hash:            h,
						NonceLen:        32,
					}

					t.Run(name, func(t *testing.T) {
						vectors[w] = GenerateTestVector(p, m.DefaultParameters(), 0)
					},
					)
					w++

					//if w >= 1 {
					//	return vectors
					//}
				}
			}
		}
	}

	return vectors
}

func TestGenerateVectorFile(t *testing.T) {
	dir := "./tests"
	file := "allVectors.json"

	vectors := GenerateAllVectors(t)
	content, _ := json.MarshalIndent(vectors, "", "    ")
	_ = ioutil.WriteFile(path.Join(dir, file), content, 0o644)
}

/*
	Test test vectors
*/

type draftConfig struct {
	EnvelopeMode string    `json:"EnvelopeMode"`
	Group        string    `json:"Group"`
	Hash         string    `json:"Hash"`
	Name         string    `json:"Name"`
	OPRF         ByteToHex `json:"OPRF"`
	SlowHash     string    `json:"SlowHash"`
}
type draftInputs struct {
	BlindLogin            ByteToHex `json:"blind_login"`
	BlindRegistration     ByteToHex `json:"blind_registration"`
	ClientIdentity        ByteToHex `json:"client_identity,omitempty"`
	ClientInfo            ByteToHex `json:"client_info"`
	ClientKeyshare        ByteToHex `json:"client_keyshare"`
	ClientNonce           ByteToHex `json:"client_nonce"`
	ClientPrivateKey      ByteToHex `json:"client_private_key"`
	ClientPrivateKeyshare ByteToHex `json:"client_private_keyshare"`
	ClientPublicKey       ByteToHex `json:"client_public_key"`
	EnvelopeNonce         ByteToHex `json:"envelope_nonce"`
	OprfKey               ByteToHex `json:"oprf_key"`
	Password              ByteToHex `json:"password"`
	ServerIdentity        ByteToHex `json:"server_identity,omitempty"`
	ServerInfo            ByteToHex `json:"server_info"`
	ServerKeyshare        ByteToHex `json:"server_keyshare"`
	ServerNonce           ByteToHex `json:"server_nonce"`
	ServerPrivateKey      ByteToHex `json:"server_private_key"`
	ServerPrivateKeyshare ByteToHex `json:"server_private_keyshare"`
	ServerPublicKey       ByteToHex `json:"server_public_key"`
}
type draftIntermediates struct {
	AuthKey             ByteToHex `json:"auth_key"`              //
	ClientMacKey        ByteToHex `json:"client_mac_key"`        //
	Envelope            ByteToHex `json:"envelope"`              //
	HandshakeEncryptKey ByteToHex `json:"handshake_encrypt_key"` //
	HandshakeSecret     ByteToHex `json:"handshake_secret"`      //
	Prk                 ByteToHex `json:"prk"`                   //
	PseudorandomPad     ByteToHex `json:"pseudorandom_pad"`      //
	ServerMacKey        ByteToHex `json:"server_mac_key"`        //
}
type draftOutputs struct {
	KE1                  ByteToHex `json:"KE1"`                   //
	KE2                  ByteToHex `json:"KE2"`                   //
	KE3                  ByteToHex `json:"KE3"`                   //
	ExportKey            ByteToHex `json:"export_key"`            //
	RegistrationRequest  ByteToHex `json:"registration_request"`  //
	RegistrationResponse ByteToHex `json:"registration_response"` //
	RegistrationUpload   ByteToHex `json:"registration_upload"`   //
	SessionKey           ByteToHex `json:"session_key"`           //
}

type draftVector struct {
	Config        draftConfig        `json:"config"`
	Inputs        draftInputs        `json:"inputs"`
	Intermediates draftIntermediates `json:"intermediates"`
	Outputs       draftOutputs       `json:"outputs"`
}

func (v *draftVector) test(t *testing.T) {
	mode, err := hex.DecodeString(v.Config.EnvelopeMode)
	if err != nil {
		t.Fatal(err)
	}

	p := &Parameters{
		OprfCiphersuite: voprf.Ciphersuite(v.Config.OPRF[1]),
		Mode:            envelope.Mode(mode[0]),
		Hash:            hashToHash(v.Config.Hash),
		NonceLen:        32,
	}

	//harden := tests.IdentityMHF

	input := v.Inputs
	check := v.Intermediates
	out := v.Outputs

	/*
		Registration
	*/

	// Client
	client := p.Client(nil)
	oprfClient := buildOPRFClient(p.OprfCiphersuite, input.BlindRegistration)
	client.Core.Oprf = oprfClient
	regReq := client.RegistrationStart(input.Password)

	if !bytes.Equal(out.RegistrationRequest, regReq.Serialize()) {
		t.Fatal("registration requests do not match")
	}

	// Server
	server := p.Server()
	regResp, _, err := server.RegistrationResponse(regReq, input.ServerPublicKey, input.OprfKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(out.RegistrationResponse, regResp.Serialize()) {
		t.Fatal("registration responses do not match")
	}

	// Client
	clientCredentials := &envelope.Credentials{
		Sk:    input.ClientPrivateKey,
		Pk:    input.ClientPublicKey,
		Idu:   input.ClientIdentity,
		Ids:   input.ServerIdentity,
		Nonce: input.EnvelopeNonce,
	}

	upload, exportKey, err := client.RegistrationFinalize(clientCredentials, regResp)
	if err != nil {
		t.Fatal(err)
	}

	pad, authKey, _, prk := client.Core.DebugGetKeys()

	if !bytes.Equal(check.Prk, prk) {
		t.Fatalf("prk do not match. expected %v,\ngot %v", check.Prk, prk)
	}

	if !bytes.Equal(check.AuthKey, authKey) {
		t.Fatal("authKeys do not match")
	}

	if !bytes.Equal(out.ExportKey, exportKey) {
		t.Fatal("exportKey do not match")
	}

	if !bytes.Equal(check.PseudorandomPad, pad) {
		t.Fatalf("pseudorandom pads do not match")
	}

	if !bytes.Equal(check.Envelope, upload.Envelope.Serialize()) {
		t.Fatalf("envelopes do not match")
	}

	if !bytes.Equal(out.RegistrationUpload, upload.Serialize()) {
		t.Fatalf("registration responses do not match")
	}

	/*
		Login
	*/

	// Client
	client = p.Client(nil)
	client.Core.Oprf = buildOPRFClient(p.OprfCiphersuite, input.BlindLogin)
	esk, err := client.Ake.Group.NewScalar().Decode(input.ClientPrivateKeyshare)
	if err != nil {
		t.Fatal(err)
	}
	client.Ake.Initialize(esk, input.ClientNonce, 32)
	KE1 := client.AuthenticationStart(input.Password, input.ClientInfo)

	if !bytes.Equal(out.KE1, KE1.Serialize()) {
		t.Fatal("KE1 do not match")
	}

	credFile := &CredentialFile{
		Ku:       input.OprfKey,
		Pku:      upload.Pku,
		Envelope: upload.Envelope,
	}

	// Server
	server = p.Server()

	serverCredentials := &envelope.Credentials{
		Sk:  input.ServerPrivateKey,
		Pk:  input.ServerPublicKey,
		Idu: input.ClientIdentity,
		Ids: input.ServerIdentity,
	}

	_ = v.loginResponse(t, server, KE1, serverCredentials, credFile)

	// Client
	cke2, err := message.DeserializeKE2(out.KE2, 32, client.Ake.Group.ElementLength(), client.Core.Hash.OutputSize())
	if err != nil {
		t.Fatal(err)
	}

	ke3, exportKey, err := client.AuthenticationFinalize(input.ClientIdentity, input.ServerIdentity, cke2)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(v.Intermediates.ClientMacKey, client.Ake.ClientMacKey) {
		t.Fatal("client mac keys do not match")
	}

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

func (v *draftVector) loginResponse(t *testing.T, s *Server, ke1 *message.KE1, creds *envelope.Credentials, credFile *CredentialFile) *message.KE2 {
	sks, err := s.Ake.Group.NewScalar().Decode(v.Inputs.ServerPrivateKeyshare)
	if err != nil {
		t.Fatal(err)
	}
	s.Ake.Initialize(sks, v.Inputs.ServerNonce, 32)

	KE2, err := s.AuthenticationResponse(ke1, v.Inputs.ServerInfo, credFile, creds)

	if !bytes.Equal(v.Intermediates.HandshakeSecret, s.Ake.HandshakeSecret) {
		t.Fatalf("HandshakeSecrets do not match : %v", s.Ake.HandshakeSecret)
	}

	if !bytes.Equal(v.Intermediates.ServerMacKey, s.Ake.ServerMacKey) {
		t.Fatal("ServerMacs do not match")
	}

	if !bytes.Equal(v.Intermediates.ClientMacKey, s.Ake.Keys.ClientMacKey) {
		t.Fatal("ClientMacs do not match")
	}

	if !bytes.Equal(v.Intermediates.HandshakeEncryptKey, s.Ake.HandshakeEncryptKey) {
		t.Fatal("HandshakeEncryptKeys do not match")
	}

	draftKE2, err := message.DeserializeKE2(v.Outputs.KE2, 32, s.Ake.Group.ElementLength(), s.Ake.Hashing.OutputSize())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(draftKE2.CredentialResponse.Serialize(), KE2.CredentialResponse.Serialize()) {
		t.Fatal("CredResp do not match")
	}

	if !bytes.Equal(draftKE2.CredentialResponse.Pks, KE2.CredentialResponse.Pks) {
		t.Fatal("pks do not match")
	}

	if !bytes.Equal(draftKE2.CredentialResponse.Data, KE2.CredentialResponse.Data) {
		t.Fatal("data do not match")
	}

	if !bytes.Equal(draftKE2.CredentialResponse.Envelope.Serialize(), KE2.CredentialResponse.Envelope.Serialize()) {
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

type draftVectors []*draftVector

func TestOpaqueVectors(t *testing.T) {
	if err := filepath.Walk("./tests/newVectors2.json",
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
				t.Run(fmt.Sprintf("%s - %s", tv.Config.Name, tv.Config.EnvelopeMode), tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}
