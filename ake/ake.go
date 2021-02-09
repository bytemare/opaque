package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/ake/hmqv"
	"github.com/bytemare/opaque/ake/sigmai"
	"github.com/bytemare/opaque/ake/tripledh"
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
		return sigmai.Name
	case TripleDH:
		return tripledh.Name
	case HMQV:
		panic(hmqv.Name)
	default:
		return ""
	}
}

func (i Identifier) Client(g ciphersuite.Identifier, h hash.Identifier, nonceLen int) *Client {
	c := &Client{
		id: i,
		Ake: &engine.Ake{
			Group:    g.Get(nil),
			Hash:     h.Get(),
			NonceLen: nonceLen,
		},
		Metadata: &engine.Metadata{},
	}

	switch i {
	case SigmaI:
		c.clientFinalize = sigmai.Finalize
	case TripleDH:
		c.clientFinalize = tripledh.Finalize
	case HMQV:
		panic("not supported")
	default:
		panic("invalid")
	}

	return c
}

func (i Identifier) Server(g group.Group, h *hash.Hash, nonceLen int) *Server {
	s := &Server{
		id: i,
		Ake: &engine.Ake{
			Group:    g,
			Hash:     h,
			NonceLen: nonceLen,
		},
		Metadata: &engine.Metadata{},
	}

	switch i {
	case SigmaI:
		s.response = sigmai.Response
		s.finalize = sigmai.ServerFinalize
	case TripleDH:
		s.response = tripledh.Response
		s.finalize = tripledh.ServerFinalize
	case HMQV:
		panic("not supported")
	default:
		panic("invalid")
	}

	return s
}

type Message interface {
	Serialize() []byte
}
