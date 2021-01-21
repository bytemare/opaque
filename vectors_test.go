package opaque

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"testing"

	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/voprf"
)

var (
	OprfSuites      = []voprf.Ciphersuite{voprf.RistrettoSha512, voprf.P256Sha256}
	Hashes          = []hash.Identifier{hash.SHA256, hash.SHA512}
	Akes            = []ake.Identifier{ake.TripleDH}
	MHF             = []mhf.MHF{mhf.Argon2id}
	SigmaSignatures = []signature.Identifier{signature.Ed25519}
	Modes           = []envelope.Mode{envelope.Base, envelope.CustomIdentifier}
)

type ByteToHex []byte

func (j ByteToHex) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(j))
}

type testEnvParameters struct {
	OPRFSuiteID  string `json:"OPRFSuite"`
	EnvHash      string `json:"EnvHash"`
	MHF          string `json:"MHF"`
	EnvelopeMode byte   `json:"EnvelopeMode"`
}

type testAkeParameters struct {
	AKE               string `json:"AKE"`
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
	Einfo2         ByteToHex      `json:"Einfo2"`
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

func GenerateTestVector(p *Parameters, m *mhf.Parameters, s signature.Identifier, mode envelope.Mode, enc encoding.Encoding) *testVector {
	params := testParameters{
		testEnvParameters: testEnvParameters{
			OPRFSuiteID:  p.OprfCiphersuite.String(),
			EnvHash:      p.Hash.String(),
			MHF:          m.String(),
			EnvelopeMode: byte(mode),
		},
		testAkeParameters: testAkeParameters{
			AKE:               p.AKE.String(),
			AkeGroup:          p.OprfCiphersuite.String(),
			AkeHash:           p.Hash.String(),
			SigmaSignatureAlg: s.String(),
		},
	}

	in := testInput{
		Idu:                   []byte("user"),
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
	in.BlindReg = client.oprf.Export().Blind[0]

	reg, err := enc.Encode(reqReg)
	if err != nil {
		panic(err)
	}
	out.RegistrationRequest = reg

	in.ClientAkeSecretKey, in.ClientAkePubkey = client.KeyGen()

	// Server
	serverOprfKeys := p.OprfCiphersuite.KeyGen()
	in.OprfKey = serverOprfKeys.SecretKey
	server := p.Server()
	in.ServerAkeSecretKey, in.ServerAkePubkey = server.KeyGen()

	respReg, err := server.RegistrationResponse(reqReg, in.ServerAkePubkey)
	if err != nil {
		panic(err)
	}

	resp, err := enc.Encode(respReg)
	if err != nil {
		panic(err)
	}

	out.RegistrationResponse = resp

	creds := &envelope.Credentials{
		Sk:  in.ClientAkeSecretKey,
		Pk:  in.ClientAkePubkey,
		Idu: in.Idu,
		Ids: in.Ids,
	}

	// Client
	upload, _, err := client.RegistrationFinalize(creds, respReg, enc)
	if err != nil {
		panic(err)
	}

	up, err := enc.Encode(upload)
	if err != nil {
		panic(err)
	}
	out.RegistrationUpload = up

	in.EnvelopeNonce = upload.Envelope.Contents.Nonce

	envU, err := enc.Encode(upload.Envelope)
	if err != nil {
		panic(err)
	}
	out.Envelope = envU

	a := &AkeRecord{
		ServerID:  in.Ids,
		SecretKey: in.ServerAkeSecretKey,
		PublicKey: in.ServerAkePubkey,
	}

	file := &CredentialFile{
		Ku:       server.OprfKey(),
		Pku:      upload.Pku,
		Envelope: upload.Envelope,
	}

	out.CredentialFile = *file

	/*
		Authentication
	*/

	// Client
	client = p.Client(m)
	reqCreds, err := client.AuthenticationStart(in.Password, nil, enc)
	if err != nil {
		panic(err)
	}

	in.BlindLog = client.oprf.Export().Blind[0]
	in.ClientEphPubkey = client.Ake.Epk.Bytes()
	in.ClientEphSecretKey = client.Ake.Esk.Bytes()
	in.ClientNonce = client.Ake.NonceU

	reqc, err := enc.Encode(reqCreds)
	if err != nil {
		panic(err)
	}
	out.CredentialRequest = reqc

	// Server
	server = p.Server()
	serverCreds := &envelope.Credentials{
		Sk:  a.SecretKey,
		Pk:  a.PublicKey,
		Idu: in.Idu,
		Ids: a.ServerID,
	}
	respCreds, err := server.AuthenticationResponse(reqCreds, nil, nil, &out.CredentialFile, serverCreds, enc)
	if err != nil {
		panic(err)
	}

	in.ServerEphPubkey = server.Ake.Epk.Bytes()
	in.ServerEphSecretKey = server.Ake.Esk.Bytes()
	in.ServerNonce = server.Ake.NonceS

	respc, err := enc.Encode(respCreds)
	if err != nil {
		panic(err)
	}
	out.CredentialResponse = respc

	// Client
	fin, exportKey, err := client.AuthenticationFinalize(in.Idu, in.Ids, respCreds, enc)
	if err != nil {
		panic(err)
	}

	finc, err := enc.Encode(fin)
	if err != nil {
		panic(err)
	}
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
	v := len(OprfSuites) * len(Hashes) * len(Akes) * len(MHF) * len(SigmaSignatures) * len(Modes)
	log.Printf("v := %v", v)
	vectors := make([]*testVector, v)
	w := 0
	for _, s := range OprfSuites {
		for _, h := range Hashes {
			for _, a := range Akes {
				for _, m := range MHF {
					// for _, sig := range SigmaSignatures {
					for _, mode := range Modes {
						var name string
						if a == ake.SigmaI {
							name = fmt.Sprintf("%d : %v-%v-%v-%v-%v-%v", w, s, h, a, m, 0, mode)
						} else {
							name = fmt.Sprintf("%d : %v-%v-%v-%v-%v", w, s, h, a, m, mode)
						}

						p := &Parameters{
							OprfCiphersuite: s,
							Hash:            h,
							AKE:             a,
							AkeGroup:        ciphersuite.Ristretto255Sha512,
							NonceLen:        32,
						}

						t.Run(name, func(t *testing.T) {
							vectors[w] = GenerateTestVector(p, m.DefaultParameters(), 0, mode, encoding.JSON)
						},
						)
						w++

						//if w >= 1 {
						//	return vectors
						//}
					}
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
