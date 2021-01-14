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

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
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
	testCredentials    `json:"Credentials"`
	UserRecord         UserRecord `json:"UserRecord"`
	testAkeSession     `json:"AkeSession"`
	testMessages       `json:"Messages"`
	ExportKey          ByteToHex `json:"ExportKey"`
	SharedSecret       ByteToHex `json:"SharedSecret"`
}

func gen3DHkeys(suite voprf.Ciphersuite) (sk, pk []byte) {
	serverAkeKeys := suite.KeyGen()
	return serverAkeKeys.SecretKey, serverAkeKeys.PublicKey
}

func genSigmaKeys(sig signature.Identifier) (sk, pk []byte) {
	s := sig.New()
	_ = s.GenerateKey()
	return s.GetPrivateKey(), s.GetPublicKey()
}

func GenerateTestVector(p *Parameters, s signature.Identifier, mode envelope.Mode) *TestVectorParameters {
	params := testParameters{
		OPRFSuiteID:       p.Ciphersuite.String(),
		Hash:              p.Hash.String(),
		MHF:               p.MHF.String(),
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
	client := p.Client()
	reqReg := client.RegistrationStart(t.Password)

	reg, err := p.Encoding.Encode(reqReg)
	if err != nil {
		panic(err)
	}
	t.RegistrationRequest = reg

	switch p.AKE {
	case ake.TripleDH:
		t.ServerAkeSecretKey, t.ServerAkePubkey = gen3DHkeys(p.Ciphersuite)
		t.ClientAkeSecretKey, t.ClientAkePubkey = client.AkeKeyGen()
	case ake.SigmaI:
		t.ServerAkeSecretKey, t.ServerAkePubkey = genSigmaKeys(signature.Ed25519)
		t.ClientAkeSecretKey, t.ClientAkePubkey = genSigmaKeys(signature.Ed25519)
	}

	// Server
	serverOprfKeys := p.Ciphersuite.KeyGen()
	t.OprfKey = serverOprfKeys.SecretKey
	server := NewServer(p.Ciphersuite, p.Hash, p.AKE, t.OprfKey, t.ServerAkeSecretKey, t.ServerAkePubkey)

	respReg, err := server.RegistrationResponse(reqReg, p.Encoding)
	if err != nil {
		panic(err)
	}

	resp, err := p.Encoding.Encode(respReg)
	if err != nil {
		panic(err)
	}

	t.RegistrationResponse = resp

	var creds message.Credentials
	switch mode {
	case envelope.Base:
		creds = message.NewClearTextCredentials(envelope.Base, t.ServerAkePubkey)
	case envelope.CustomIdentifier:
		creds = message.NewClearTextCredentials(envelope.CustomIdentifier, t.ServerAkePubkey, t.Idu, t.Ids)
	}

	// Client
	upload, _, err := client.RegistrationFinalize(t.ClientAkeSecretKey, t.ClientAkePubkey, creds, respReg, p.Encoding)
	if err != nil {
		panic(err)
	}

	up, err := p.Encoding.Encode(upload)
	if err != nil {
		panic(err)
	}
	t.RegistrationUpload = up

	t.EnvelopeMode = byte(mode)
	t.EnvelopeNonce = upload.Envelope.Contents.Nonce

	envU, err := p.Encoding.Encode(upload.Envelope)
	if err != nil {
		panic(err)
	}
	t.Envelope = envU

	userRecord, akeRecord, err := server.RegistrationFinalize(credentials.Username, credentials.Idu, credentials.Ids, p, upload, p.Encoding)
	if err != nil {
		panic(err)
	}

	t.UserRecord = *userRecord

	AkeRecords[string(akeRecord.ID)] = akeRecord
	Users[string(credentials.Username)] = userRecord

	// Authentication

	// Client
	client = p.Client()
	username := string(credentials.Username)
	reqCreds, err := client.AuthenticationStart(t.Password, nil, p.Encoding)
	if err != nil {
		panic(err)
	}

	x := client.client.Oprf.Export()

	t.BlindingFactor = x.Blind[0]
	t.ClientEphPubkey = client.client.Ake.Epk.Bytes()
	t.ClientEphSecretKey = client.client.Ake.Esk.Bytes()
	t.ClientNonce = client.client.Ake.NonceU

	reqc, err := p.Encoding.Encode(reqCreds)
	if err != nil {
		panic(err)
	}
	t.CredentialRequest = reqc

	// Server
	user := Users[username]
	server = user.Server()
	//server = NewServer(suite, h, ke, t.OprfKey, t.ServerAkeSecretKey, t.ServerAkePubkey)
	respCreds, err := server.AuthenticationResponse(reqCreds, &upload.Envelope, creds, nil, nil, t.ClientAkePubkey, p.Encoding)
	if err != nil {
		panic(err)
	}

	t.ServerEphPubkey = server.server.Ake.Epk.Bytes()
	t.ServerEphSecretKey = server.server.Ake.Esk.Bytes()
	t.ServerNonce = server.server.Ake.NonceS

	respc, err := p.Encoding.Encode(respCreds)
	if err != nil {
		panic(err)
	}
	t.CredentialResponse = respc

	// Client
	fin, exportKey, err := client.AuthenticationFinalize(creds, respCreds, p.Encoding)
	if err != nil {
		panic(err)
	}

	finc, err := p.Encoding.Encode(fin)
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
					//for _, sig := range SigmaSignatures {
						for _, mode := range Modes {
							var name string
							if a == ake.SigmaI {
								name = fmt.Sprintf("%d : %v-%v-%v-%v-%v-%v", w, s, h, a, m, 0, mode)
							} else {
								name = fmt.Sprintf("%d : %v-%v-%v-%v-%v", w, s, h, a, m, mode)
							}

							p := &Parameters{
								Ciphersuite: s,
								Hash:        h,
								MHF:         m.DefaultParameters(),
								AKE:         a,
								Encoding:    encoding.JSON,
							}

							t.Run(name, func(t *testing.T) {
								vectors[w] = GenerateTestVector(p, 0, mode)
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
