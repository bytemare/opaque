package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/opaque/ake/internal/sigmai"
	"github.com/bytemare/opaque/ake/internal/tripledh"
	"github.com/bytemare/opaque/internal"
)

type Identifier byte

const (
	SigmaI Identifier = 1 + iota
	TripleDH
	HMQV

	sSigmaI   = "Sigma-I"
	sTripleDH = "3DH"
	sHMQV     = "HMQV"
)

func (i Identifier) String() string {
	switch i {
	case SigmaI:
		return sSigmaI
	case TripleDH:
		return sTripleDH
	case HMQV:
		panic(sHMQV)
	default:
		return ""
	}
}

func (i Identifier) Client(g group.Group, h *hash.Hash) *Client {
	c := &Client{
		id: i,
		Core: &internal.Core{
			Group: g,
			Hash:  h,
		},
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

func (i Identifier) Server(g group.Group, h *hash.Hash, privateKey []byte) *Server {
	s := &Server{
		id: i,
		Core: &internal.Core{
			Group: g,
			Hash:  h,
		},
		sk: privateKey,
	}

	switch i {
	case SigmaI:
		s.SigmaServer = internal.SigmaServer{Identifier: signature.Ed25519}
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
