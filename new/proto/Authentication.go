package proto

import (
	"crypto/hmac"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/new/message"
	"github.com/bytemare/voprf"
)

func CreateCredentialRequest(password []byte) (*message.CredentialRequest, []byte) {
	var err error

	client, err = voprf.RistrettoSha512.Client(nil)
	if err != nil {
		panic(err)
	}

	m := client.Blind(password)

	cr := &message.CredentialRequest{Data: m}

	return cr, client.Export().Blind[0]
}

func CreateCredentialResponse(req *message.CredentialRequest, ku, pku []byte, envU *message.Envelope) *message.CredentialResponse {
	server, err := voprf.RistrettoSha512.Server(ku)
	if err != nil {
		panic(err)
	}

	evaluation, err := server.Evaluate(req.Data)
	if err != nil {
		panic(err)
	}

	z, err := evaluation.Encode(encoding.JSON)
	if err != nil {
		panic(err)
	}

	return &message.CredentialResponse{
		Data:     z,
		Envelope: envU,
	}
}

func RecoverCredentials(password, blind []byte,
	req *message.CredentialRequest, resp *message.CredentialResponse) (*message.Credentials, []byte) {
	// TODO: req is not used here

	// 1 + 2
	ev, err := voprf.DecodeEvaluation(resp.Data, encoding.JSON)
	if err != nil {
		panic(err)
	}

	n, err := client.Finalize(ev, []byte("OPAQUE00"))
	if err != nil {
		panic(err)
	}

	// 3, 4, 5
	contents := resp.Envelope.Contents
	nonce := contents.Nonce
	ct := contents.Ct

	// 6
	hardened := cipher.IHF.Hash(n, nil)
	rwdU := cipher.Hash.HKDFExtract(hardened, []byte("rwdu"))

	// 7
	pad := cipher.Hash.HKDFExpand(rwdU, append(nonce, []byte("Pad")...), len(ct))

	// 8
	authKey := cipher.Hash.HKDFExpand(rwdU, append(nonce, []byte("AuthKey")...), cipher.Hash.OutputSize())

	// 9
	exportKey := cipher.Hash.HKDFExpand(rwdU, append(nonce, []byte("ExportKey")...), cipher.Hash.OutputSize())

	// 10
	encIn, err := encoding.JSON.Encode(contents)
	if err != nil {
		panic(err)
	}
	expectedTag := cipher.Hash.Hmac(encIn, authKey)

	// 11
	if !hmac.Equal(expectedTag, resp.Envelope.AuthTag) {
		panic("invalid tag")
	}

	// 12
	pt := xor(ct, pad)

	// 13
	secrets, err := message.DeserializeCredentialExtension(pt, encoding.JSON)
	if err != nil {
		panic(err)
	}

	// 14
	clear, err := message.DeserializeCredentialExtension(contents.AuthData, encoding.JSON)
	if err != nil {
		panic(err)
	}

	//15
	creds := &message.Credentials{
		CleartextCredentials: *clear,
		SecretCredentials:    *secrets,
	}

	// 16
	return creds, exportKey
}
