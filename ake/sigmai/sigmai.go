package sigmai

import (
	"crypto/hmac"
	"errors"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/opaque/internal"
)

const (
	Name          = "Sigma-I"
	keyTag        = "SIGMA-I keys"
	encryptionTag = "encryption key"
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

type Ke2 struct {
	NonceS    []byte `json:"n"`
	EpkS      []byte `json:"e"`
	EInfo     []byte `json:"i,omitempty"`
	Signature []byte `json:"s"`
	Mac       []byte `json:"m"`
}

func (k Ke2) Serialize() []byte {
	return utils.Concatenate(0, k.NonceS, k.EpkS, internal.EncodeVector(k.EInfo), k.Signature, k.Mac)
}

func DeserializeKe2(in []byte, nonceLength, elementLength, signatureLength, macLength int) (*Ke2, error) {
	nonceS := in[0:nonceLength]
	offset := nonceLength
	epks := in[offset : offset+elementLength]
	offset = offset + elementLength
	einfo, eOffset := internal.DecodeVector(in[offset:])
	offset = nonceLength + elementLength + eOffset
	sig := in[offset : offset+signatureLength]
	offset = offset + signatureLength
	mac := in[offset:]
	if len(mac) != macLength {
		return nil, errors.New("invalid mac length")
	}

	return &Ke2{
		NonceS:    nonceS,
		EpkS:      epks,
		EInfo:     einfo,
		Signature: sig,
		Mac:       mac,
	}, nil
}

type Ke3 struct {
	Signature []byte `json:"s"`
	Mac       []byte `json:"m"`
}

func (k Ke3) Serialize() []byte {
	return append(k.Signature, k.Mac...)
}

func DeserializeKe3(in []byte, signatureLength, macLength int) (*Ke3, error) {
	if len(in) != signatureLength+macLength {
		return nil, errors.New("ke3 is too short")
	}

	sig := in[:signatureLength]
	mac := in[signatureLength:]

	return &Ke3{
		Signature: sig,
		Mac:       mac,
	}, nil
}
