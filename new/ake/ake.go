package ake

import "github.com/bytemare/cryptotools/hash"

func label(label string) []byte {
	return []byte("OPAQUE" + label)
}

type HkdfLabel struct {
	length  uint16
	label   []byte
	context []byte
}

func HKDFExpand(h *hash.Hash, secret, hkdfLabel []byte, length int) []byte {
	return h.HKDFExpand(secret, hkdfLabel, length)
}

func HKDFExpandLabel(h *hash.Hash, secret, label, context []byte, length int) []byte {
	return HKDFExpand(h, secret, append([]byte("OPAQUE "), label...), length)
}

func DeriveSecret(h *hash.Hash, secret, label, transcript []byte) []byte {
	return HKDFExpandLabel(h, secret, label, h.Hash(0, transcript), h.OutputSize())
}
