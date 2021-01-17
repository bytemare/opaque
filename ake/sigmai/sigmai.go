package sigmai

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/opaque/internal"
)

const (
	Name   = "Sigma-I"
	keyTag = "SIGMA-I keys"
)

var (
	sig = signature.Ed25519

	tagSigmaI = []byte(keyTag)

	ErrSigmaInvServerSig = errors.New("invalid server signature")
	ErrSigmaInvClientSig = errors.New("invalid client signature")
)

func KeyGen() (sk, pk []byte) {
	s := sig.New()
	s.GenerateKey()

	return s.GetPrivateKey(), s.GetPublicKey()
}

func kSigma(g group.Group, esk group.Scalar, epkp []byte) ([]byte, error) {
	e, err := g.NewElement().Decode(epkp)
	if err != nil {
		return nil, err
	}

	return e.Mult(esk).Bytes(), nil
}

func checkHmac(h *hash.Hash, ids, key, mac []byte) bool {
	expectedHmac := h.Hmac(ids, key)
	return hmac.Equal(expectedHmac, mac)
}

func encode(k interface{}, enc encoding.Encoding) []byte {
	output, err := enc.Encode(k)
	if err != nil {
		panic(err)
	}

	return output
}

type Ke2 struct {
	NonceS    []byte `json:"n"`
	EpkS      []byte `json:"e"`
	Signature []byte `json:"s"`
	Mac       []byte `json:"m"`
}

func (k *Ke2) Encode(enc encoding.Encoding) []byte {
	return encode(k, enc)
}

func Decodeke2(input []byte, enc encoding.Encoding) (*Ke2, error) {
	d, err := enc.Decode(input, &Ke2{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*Ke2)
	if !ok {
		return nil, internal.ErrAssertKe2
	}

	return de, nil
}

type Ke3 struct {
	Signature []byte `json:"s"`
	Mac       []byte `json:"m"`
}

func (k Ke3) Encode(enc encoding.Encoding) []byte {
	return encode(k, enc)
}

func DecodeKe3(input []byte, enc encoding.Encoding) (*Ke3, error) {
	d, err := enc.Decode(input, &Ke3{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*Ke3)
	if !ok {
		return nil, internal.ErrAssertKe3
	}

	return de, nil
}
