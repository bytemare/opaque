package sigmai

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/internal"
)

const SigmaKeyTag = "SIGMA-I keys"

var (
	tagSigmaI = []byte(SigmaKeyTag)

	ErrSigmaInvServerSig = errors.New("invalid server signature")
	ErrSigmaInvClientSig = errors.New("invalid client signature")
)

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

type ke2 struct {
	NonceS    []byte `json:"n"`
	EpkS      []byte `json:"e"`
	Signature []byte `json:"s"`
	Mac       []byte `json:"m"`
}

func (k *ke2) Encode(enc encoding.Encoding) []byte {
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
	Signature []byte `json:"s"`
	Mac       []byte `json:"m"`
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
