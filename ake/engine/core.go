package engine

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

const (
	labelPrefix  = "OPAQUE"
	tagHandshake = "handshake secret"
	tagSession   = "session secret"
	tagMacServer = "server mac"
	tagMacClient = "client mac"
	tagEncServer = "server enc"

	aeadNonceSize = 16
)

type Ake struct {
	group.Group
	*hash.Hash
	NonceLen      int
	NonceU        []byte
	NonceS        []byte
	Esk           group.Scalar
	Epk           group.Element
	Km2, Km3      []byte
	Ke2           []byte
	SessionSecret []byte
	Transcript2   []byte
	Transcript3   []byte
	Idu, Pku      []byte // Used by Sigma
}

func (c *Ake) DeriveKeys(m *Metadata, tag, nonceU, nonceS, ikm []byte) {
	info := info(tag, nonceU, nonceS, m.IDu, m.IDs)
	handshakeSecret := hkdfExpandLabel(c.Hash, ikm, c.Hash.Hash(0, info), tagHandshake)
	c.SessionSecret = hkdfExpandLabel(c.Hash, ikm, c.Hash.Hash(0, info), tagSession)
	c.Km2 = hkdfExpandLabel(c.Hash, handshakeSecret, []byte(""), tagMacServer)
	c.Km3 = hkdfExpandLabel(c.Hash, handshakeSecret, []byte(""), tagMacClient)
	c.Ke2 = hkdfExpandLabel(c.Hash, handshakeSecret, []byte(""), tagEncServer)
}

func lengthPrefixEncode(input []byte) []byte {
	return append(encoding.I2OSP2(uint(len(input))), input...)
}

func info(protoTag, nonceU, nonceS, idU, idS []byte) []byte {
	return utils.Concatenate(0, protoTag,
		lengthPrefixEncode(nonceU), lengthPrefixEncode(nonceS),
		lengthPrefixEncode(idU), lengthPrefixEncode(idS))
}

func buildLabel(label string) []byte {
	return []byte(labelPrefix + label)
}

type HkdfLabel struct {
	length  uint16
	label   []byte
	context []byte // todo: what is this context ?
}

func hkdfExpand(h *hash.Hash, secret, hkdfLabel []byte) []byte {
	return h.HKDFExpand(secret, hkdfLabel, h.OutputSize())
}

func hkdfExpandLabel(h *hash.Hash, secret, context []byte, label string) []byte {
	return hkdfExpand(h, secret, buildLabel(label))
}

type Ke1 struct {
	NonceU []byte `json:"n"`
	EpkU   []byte `json:"e"`
}

func encode(k interface{}, enc encoding.Encoding) []byte {
	output, err := enc.Encode(k)
	if err != nil {
		panic(err)
	}

	return output
}

func (k Ke1) Encode(enc encoding.Encoding) []byte {
	return encode(k, enc)
}

func DecodeKe1(input []byte, enc encoding.Encoding) (*Ke1, error) {
	d, err := enc.Decode(input, &Ke1{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*Ke1)
	if !ok {
		return nil, internal.ErrAssertKe1
	}

	return de, nil
}

func AesGcmEncrypt(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aeadNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	return append(nonce, aesgcm.Seal(nil, nonce, plaintext, nil)...)
}

func AesGcmDecrypt(key, ciphertext []byte) ([]byte, error) {
	nonce := ciphertext[:aeadNonceSize]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[aeadNonceSize:], nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
