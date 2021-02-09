package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake/hmqv"
	"github.com/bytemare/opaque/ake/sigmai"
)

type Identifier byte

const (
	SigmaI Identifier = 1 + iota
	TripleDH
	HMQV
)

func (i Identifier) String() string {
	switch i {
	case SigmaI:
		panic(sigmai.Name)
	case TripleDH:
		return Name
	case HMQV:
		panic(hmqv.Name)
	default:
		return ""
	}
}

func (i Identifier) Client(g ciphersuite.Identifier, h hash.Identifier, nonceLen int) *Client {
	c := &Client{
		id: i,
		Ake: &Ake{
			Group:    g.Get(nil),
			Hash:     h.Get(),
			NonceLen: nonceLen,
		},
		Metadata: &Metadata{},
	}

	return c
}

func (i Identifier) Server(g group.Group, h *hash.Hash, nonceLen int) *Server {
	s := &Server{
		id: i,
		Ake: &Ake{
			Group:    g,
			Hash:     h,
			NonceLen: nonceLen,
		},
		Metadata: &Metadata{},
	}

	return s
}

type Message interface {
	Serialize() []byte
}
