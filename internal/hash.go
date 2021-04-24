package internal

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
)

func Concat(nonce []byte, tag string) []byte {
	t := []byte(tag)
	e := make([]byte, 0, len(nonce)+len(t))
	e = append(e, nonce...)
	e = append(e, t...)

	return e
}

type KDF struct {
	H *hash.Hash
}

func (k *KDF) Extract(salt, ikm []byte) []byte {
	return k.H.HKDFExtract(ikm, salt)
}

func (k *KDF) Expand(data, info []byte, length int) []byte {
	return k.H.HKDFExpand(data, info, length)
}

func (k *KDF) Size() int {
	return k.H.OutputSize()
}

type Mac struct {
	*hash.Hash
}

func (m *Mac) MAC(key, message []byte) []byte {
	return m.Hmac(message, key)
}

func (m *Mac) Size() int {
	return m.OutputSize()
}

type Hash struct {
	H *hash.Hash
}

func (h *Hash) Hash(message []byte) []byte {
	return h.H.Hash(message)
}

func (h *Hash) Size() int {
	return h.H.OutputSize()
}

type MHF struct {
	*mhf.MHF
}
