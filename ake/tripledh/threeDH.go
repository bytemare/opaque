package tripledh

import (
	"crypto/hmac"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/opaque/internal"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
)

const (
	Name = "3DH"

	keyTag = "3DH keys"
)

var tag3DH = []byte(keyTag)

func KeyGen(g group.Group) (secretKey, publicKey []byte) {
	sk := g.NewScalar().Random()
	secretKey = sk.Bytes()
	publicKey = g.Base().Mult(sk).Bytes()

	return
}

func checkHmac(h *hash.Hash, transcript2, key, mac []byte) bool {
	expectedHmac2 := h.Hmac(transcript2, key)
	return hmac.Equal(expectedHmac2, mac)
}

func encode(k interface{}, enc encoding.Encoding) []byte {
	output, err := enc.Encode(k)
	if err != nil {
		panic(err)
	}

	return output
}

type Ke2 struct {
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Mac    []byte `json:"m"`
}

func (k Ke2) Encode(enc encoding.Encoding) []byte {
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
	Mac []byte `json:"m"`
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
