package tripledh

import (
	"crypto/hmac"

	"github.com/bytemare/opaque/internal"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
)

const keyTag = "3DH keys"

var tag3DH = []byte(keyTag)

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

type ke2 struct {
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Mac    []byte `json:"m"`
}

func (k ke2) Encode(enc encoding.Encoding) []byte {
	return encode(k, enc)
}

func decodeke2(input []byte, enc encoding.Encoding) (*ke2, error) {
	d, err := enc.Decode(input, &ke2{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*ke2)
	if !ok {
		return nil, internal.ErrAssertKe2
	}

	return de, nil
}

type ke3 struct {
	Mac []byte `json:"m"`
}

func (k ke3) Encode(enc encoding.Encoding) []byte {
	return encode(k, enc)
}

func decodeKe3(input []byte, enc encoding.Encoding) (*ke3, error) {
	d, err := enc.Decode(input, &ke3{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*ke3)
	if !ok {
		return nil, internal.ErrAssertKe3
	}

	return de, nil
}
