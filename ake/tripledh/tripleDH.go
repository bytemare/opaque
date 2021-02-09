package tripledh

import (
	"crypto/hmac"
	"errors"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/opaque/internal"

	"github.com/bytemare/cryptotools/hash"
)

const (
	Name          = "3DH"
	keyTag        = "3DH keys"
	encryptionTag = "encryption pad"
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

type Ke2 struct {
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Einfo  []byte `json:"i"`
	Mac    []byte `json:"m"`
}

func (k Ke2) Serialize() []byte {
	return utils.Concatenate(0, k.NonceS, k.EpkS, internal.EncodeVector(k.Einfo), k.Mac)
}

func DeserializeKe2(in []byte, nonceLength, elementLength, hashSize int) (*Ke2, error) {
	nonceS := in[0:nonceLength]
	epks := in[nonceLength : nonceLength+elementLength]
	einfo, offset := internal.DecodeVector(in[nonceLength+elementLength:])
	mac := in[nonceLength+elementLength+offset:]
	if len(mac) != hashSize {
		return nil, errors.New("invalid mac length")
	}

	return &Ke2{
		NonceS: nonceS,
		EpkS:   epks,
		Einfo:  einfo,
		Mac:    mac,
	}, nil
}

type Ke3 struct {
	Mac []byte `json:"m"`
}

func (k Ke3) Serialize() []byte {
	return k.Mac
}

func DeserializeKe3(in []byte, hashSize int) (*Ke3, error) {
	if len(in) != hashSize {
		return nil, errors.New("invalid mac length")
	}

	return &Ke3{Mac: in}, nil
}
