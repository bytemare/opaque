package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
)

const (
	keyTag        = "3DH keys"
	encryptionTag = "encryption pad"
)

var tag3DH = []byte(keyTag)

func NewClient(g ciphersuite.Identifier, h hash.Identifier, nonceLen int) *Client {
	c := &Client{
		Ake: &Ake{
			Group:    g.Get(nil),
			Hash:     h.Get(),
			NonceLen: nonceLen,
		},
		Metadata: &Metadata{},
	}

	return c
}

func NewServer(g group.Group, h hash.Identifier, nonceLen int) *Server {
	s := &Server{
		Ake: &Ake{
			Group:    g,
			Hash:     h.Get(),
			NonceLen: nonceLen,
		},
		Metadata: &Metadata{},
	}

	return s
}

func KeyGen(g group.Group) (sk, pk []byte) {
	scalar := g.NewScalar().Random()
	publicKey := g.Base().Mult(scalar)

	return scalar.Bytes(), publicKey.Bytes()
}
