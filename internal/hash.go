package internal

import (
	"github.com/bytemare/cryptotools/hash"
)

type KDF struct {
	*hash.Hash
}

func (k *KDF) Extract(salt, ikm []byte) []byte {
	return k.HKDFExtract(ikm, salt)
}

func (k *KDF) Expand(data, info []byte, length int) []byte {
	return k.HKDFExpand(data, info, length)
}

func (k *KDF) Size() int {
	return k.OutputSize()
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

func NewHash(id hash.Hashing) *Hash {
	return &Hash{id.Get()}
}

func (h *Hash) Hash(message []byte) []byte {
	return h.H.Hash(message)
}

func (h *Hash) Size() int {
	return h.H.OutputSize()
}
