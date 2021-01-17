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

type testParameters struct {
	OPRFSuiteID       string `json:"OPRFSuite"`
	Hash              string `json:"Hash"`
	MHF               string `json:"MHF"`
	AKE               string `json:"AKE"`
	SigmaSignatureAlg string `json:"SigmaSignatureAlg,omitempty"`
}

type testCredentials struct {
	Username       ByteToHex `json:"Username"`
	Idu            ByteToHex `json:"Idu"`
	Ids            ByteToHex `json:"Ids"`
	Password       ByteToHex `json:"Password"`
	BlindingFactor ByteToHex `json:"BlindingFactor"`
	OprfKey        ByteToHex `json:"OprfKey"`
	EnvelopeMode   byte      `json:"EnvelopeMode"`
	EnvelopeNonce  ByteToHex `json:"EnvelopeNonce"`
	Envelope       ByteToHex `json:"Envelope"`
}

type testAkeSession struct {
	ClientEphPubkey    ByteToHex `json:"ClientEphPubkey"`
	ClientEphSecretKey ByteToHex `json:"ClientEphSecretKey"`
	ServerEphPubkey    ByteToHex `json:"ServerEphPubkey"`
	ServerEphSecretKey ByteToHex `json:"ServerEphSecretKey"`
	ClientNonce        ByteToHex `json:"ClientNonce"`
	ServerNonce        ByteToHex `json:"ServerNonce"`
	Info1              ByteToHex `json:"Info1"`
	Info2              ByteToHex `json:"Info2"`
	Einfo2             ByteToHex `json:"Einfo2"`
}

type testMessages struct {
	RegistrationRequest  ByteToHex `json:"RegistrationRequest"`
	RegistrationResponse ByteToHex `json:"RegistrationResponse"`
	RegistrationUpload   ByteToHex `json:"RegistrationUpload"`
	CredentialRequest    ByteToHex `json:"CredentialRequest"`
	CredentialResponse   ByteToHex `json:"CredentialResponse"`
	KeyExchange          ByteToHex `json:"KeyExchange"`
}

type TestVectorParameters struct {
	testParameters     `json:"parameters"`
	ClientAkePubkey    ByteToHex `json:"ClientAkePubkey"`
	ClientAkeSecretKey ByteToHex `json:"ClientAkeSecretKEy"`
	ServerAkePubkey    ByteToHex `json:"ServerAkePubkey"`
	ServerAkeSecretKey ByteToHex `json:"ServerAkeSecretKEy"`
	testCredentials    `json:"CleartextCredentials"`
	UserRecord         UserRecord `json:"UserRecord"`
	testAkeSession     `json:"AkeSession"`
	testMessages       `json:"Messages"`
	ExportKey          ByteToHex `json:"ExportKey"`
	SharedSecret       ByteToHex `json:"SharedSecret"`
}

func GenerateTestVector(p *Parameters, m *mhf.Parameters, s signature.Identifier, mode envelope.Mode, enc encoding.Encoding) *TestVectorParameters {
	params := testParameters{
		OPRFSuiteID:       p.OprfCiphersuite.String(),
		Hash:              p.Hash.String(),
		MHF:               m.String(),
		AKE:               p.AKE.String(),
		SigmaSignatureAlg: s.String(),
	}

	credentials := testCredentials{
		Username: []byte("user"),
		Idu:      utils.RandomBytes(32),
		Ids:      []byte("server"),
		Password: utils.RandomBytes(8),
	}

	t := &TestVectorParameters{
		testParameters:  params,
		testCredentials: credentials,
		testAkeSession:  testAkeSession{},
		testMessages:    testMessages{},
	}

	// Client
	client := p.Client(m)
	reqReg := client.RegistrationStart(t.Password)

	reg, err := enc.Encode(reqReg)
	if err != nil {
		panic(err)
	}
	t.RegistrationRequest = reg

	t.ClientAkeSecretKey, t.ClientAkePubkey = client.KeyGen()

	// Server
	serverOprfKeys := p.OprfCiphersuite.KeyGen()
	t.OprfKey = serverOprfKeys.SecretKey
	server := p.Server()
	t.ServerAkeSecretKey, t.ServerAkePubkey = server.KeyGen()

	respReg, err := server.RegistrationResponse(reqReg, t.ServerAkePubkey)
	if err != nil {
		panic(err)
	}

	resp, err := enc.Encode(respReg)
	if err != nil {
		panic(err)
	}

	t.RegistrationResponse = resp

	creds := &envelope.Credentials{
		Sk:  t.ClientAkeSecretKey,
		Pk:  t.ClientAkePubkey,
		Idu: t.Idu,
		Ids: t.Ids,
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
	t.RegistrationUpload = up

	t.EnvelopeMode = byte(mode)
	t.EnvelopeNonce = upload.Envelope.Contents.Nonce

	envU, err := enc.Encode(upload.Envelope)
	if err != nil {
		panic(err)
	}
	t.Envelope = envU

	a := &AkeRecord{
		ServerID:  t.Ids,
		SecretKey: t.ServerAkeSecretKey,
		PublicKey: t.ServerAkePubkey,
	}

	file := &CredentialFile{
		Ku:       server.OprfKey(),
		Pku:      upload.Pku,
		Envelope: upload.Envelope,
	}

	t.UserRecord = UserRecord{
		HumanUserID:    t.Username,
		UUID:           t.Idu,
		ServerAkeID:    a.ServerID,
		CredentialFile: *file,
		Parameters:     *p,
	}

	// Authentication

	// Client
	client = p.Client(m)
	reqCreds, err := client.AuthenticationStart(t.Password, nil, enc)
	if err != nil {
		panic(err)
	}

	x := client.oprf.Export()

	t.BlindingFactor = x.Blind[0]
	t.ClientEphPubkey = client.Ake.Epk.Bytes()
	t.ClientEphSecretKey = client.Ake.Esk.Bytes()
	t.ClientNonce = client.Ake.NonceU

	reqc, err := enc.Encode(reqCreds)
	if err != nil {
		panic(err)
	}
	t.CredentialRequest = reqc

	// Server
	server = p.Server()
	serverCreds := &envelope.Credentials{
		Sk:  a.SecretKey,
		Pk:  a.PublicKey,
		Idu: t.UserRecord.UUID,
		Ids: a.ServerID,
	}
	respCreds, err := server.AuthenticationResponse(reqCreds, nil, nil, &t.UserRecord.CredentialFile, serverCreds, enc)
	if err != nil {
		panic(err)
	}

	t.ServerEphPubkey = server.Ake.Epk.Bytes()
	t.ServerEphSecretKey = server.Ake.Esk.Bytes()
	t.ServerNonce = server.Ake.NonceS

	respc, err := enc.Encode(respCreds)
	if err != nil {
		panic(err)
	}
	t.CredentialResponse = respc

	// Client
	fin, exportKey, err := client.AuthenticationFinalize(t.Idu, t.Ids, respCreds, enc)
	if err != nil {
		panic(err)
	}

	finc, err := enc.Encode(fin)
	if err != nil {
		panic(err)
	}
	t.KeyExchange = finc

	t.ExportKey = exportKey

	if !bytes.Equal(client.SessionKey(), server.SessionKey()) {
		panic("Session secrets don't match.")
	}

	t.SharedSecret = client.SessionKey()

	return t
}

func GenerateAllVectors(t *testing.T) []*TestVectorParameters {
	v := len(OprfSuites) * len(Hashes) * len(Akes) * len(MHF) * len(SigmaSignatures) * len(Modes)
	log.Printf("v := %v", v)
	vectors := make([]*TestVectorParameters, v)
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
