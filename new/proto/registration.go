package proto

import (
	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hashtogroup"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/new/message"
	"github.com/bytemare/voprf"
)

var (
	client *voprf.Client
	cipher *cryptotools.Ciphersuite
)

const (
	protocol = "OPAQUE"
	version  = "00"
)

func init() {
	var err error
	g := hashtogroup.Ristretto255Sha512

	dst, err := g.MakeDST(protocol, version)
	if err != nil {
		panic(err)
	}

	cipher, err = cryptotools.New(nil, dst)
	if err != nil {
		panic(err)
	}
}

func CreateRegistrationRequest(password []byte) (*message.RegistrationRequest, []byte) {
	var err error

	client, err = voprf.RistrettoSha512.Client(nil)
	if err != nil {
		panic(err)
	}

	m := client.Blind(password)

	rr := &message.RegistrationRequest{Data: m}

	return rr, client.Export().Blind[0]
}

func CreateRegistrationResponse(req *message.RegistrationRequest, sks, pks []byte) *message.RegistrationResponse {
	server, err := voprf.RistrettoSha512.Server(sks)
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

	secrets := []message.CredentialType{message.Idu, message.Sku, message.Pku, message.Ids}
	clear := []message.CredentialType{message.Pks}

	response := &message.RegistrationResponse{
		Data:           z,
		Pks:            pks,
		SecretTypes:    secrets,
		CleartextTypes: clear,
	}

	return response
}

func FinalizeRequest(_, secret, _ []byte,
	req *message.RegistrationRequest, resp *message.RegistrationResponse) (*message.RegistrationUpload, []byte) {
	//TODO: req is not used here

	// 1 + 2
	ev, err := voprf.DecodeEvaluation(resp.Data, encoding.JSON)
	if err != nil {
		panic(err)
	}

	n, err := client.Finalize(ev, []byte("OPAQUE00"))
	if err != nil {
		panic(err)
	}

	// 3
	hardened := cipher.IHF.Hash(n, nil)
	rwdU := cipher.Hash.HKDFExtract(hardened, []byte("rwdu"))

	// 4
	if secret == nil {
		secret = cipher.HashToScalar(rwdU).Bytes()
	}

	sext := []message.CredentialExtension{
		{
			T:    message.Sku,
			Data: secret,
		},
	}

	clear := []message.CredentialExtension{
		{
			T:    message.Pks,
			Data: resp.Pks,
		},
	}

	// 6
	pt, err := encoding.JSON.Encode(sext)
	if err != nil {
		panic(err)
	}

	// 7
	nonce := utils.RandomBytes(32)

	// 8
	pad := cipher.Hash.HKDFExpand(rwdU, append(nonce, []byte("Pad")...), len(pt))

	// 9
	authKey := cipher.Hash.HKDFExpand(rwdU, append(nonce, []byte("AuthKey")...), cipher.Hash.OutputSize())

	// 10
	exportKey := cipher.Hash.HKDFExpand(rwdU, append(nonce, []byte("ExportKey")...), cipher.Hash.OutputSize())

	// 11
	ct := xor(pt, pad)

	// 12
	authData, err := encoding.JSON.Encode(clear)
	if err != nil {
		panic(err)
	}

	// 13
	in := message.InnerEnvelope{
		Nonce:    nonce,
		Ct:       ct,
		AuthData: authData,
	}

	encIn, err := encoding.JSON.Encode(in)
	if err != nil {
		panic(err)
	}

	// 14
	tag := cipher.Hash.Hmac(encIn, authKey)

	// 15
	envU := &message.Envelope{
		Contents: in,
		AuthTag:  tag,
	}

	// 16
	up := &message.RegistrationUpload{
		Envelope: envU,
		Pku:      nil,
	}

	// 17
	return up, exportKey
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xoring slices must be of same length")
	}

	dst := make([]byte, len(a))

	// if the size is fixed, we could unroll the loop
	for i, r := range a {
		dst[i] = r ^ b[i]
	}

	return dst
}
