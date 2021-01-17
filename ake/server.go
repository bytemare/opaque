package ake

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/ake/sigmai"
	"github.com/bytemare/opaque/ake/tripledh"
)

type (
	response       func(core *engine.Ake, m *engine.Metadata, sk, pku, req, info2 []byte, enc encoding.Encoding) ([]byte, []byte, error)
	serverFinalize func(core *engine.Ake, req []byte, enc encoding.Encoding) error
)

type Server struct {
	id Identifier
	*engine.Ake
	*engine.Metadata
	response
	finalize serverFinalize
}

func (s *Server) Identifier() Identifier {
	return s.id
}

func (s *Server) Response(sk, pku, req, info2 []byte, enc encoding.Encoding) (encKe2, einfo2 []byte, err error) {
	return s.response(s.Ake, s.Metadata, sk, pku, req, info2, enc)
}

func (s *Server) Finalize(req []byte, enc encoding.Encoding) error {
	return s.finalize(s.Ake, req, enc)
}

func (s *Server) KeyGen() (sk, pk []byte) {
	switch s.Identifier() {
	case SigmaI:
		return sigmai.KeyGen()
	case TripleDH:
		return tripledh.KeyGen(s.Group)
	default:
		panic("invalid")
	}
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}
