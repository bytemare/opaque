package internal

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
)

func Concat(a []byte, b string) []byte {
	t := []byte(b)
	e := make([]byte, 0, len(a)+len(t))
	e = append(e, a...)
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
	H *hash.Hash
}

func (m *Mac) MAC(key, message []byte) []byte {
	return m.H.Hmac(message, key)
}

func (m *Mac) Size() int {
	return m.H.OutputSize()
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

func (h *Hash) Sum() []byte {
	return h.H.Sum(nil)
}

func (h *Hash) Write(p []byte) {
	_, _ = h.H.Write(p)
}

type MHF struct {
	*mhf.MHF
}
