package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/opaque/ake/engine"
	"github.com/bytemare/opaque/ake/sigmai"
	"github.com/bytemare/opaque/ake/tripledh"
)

type (
	response       func(core *engine.Ake, m *engine.Metadata, sk, pku, req, serverInfo []byte) ([]byte, error)
	serverFinalize func(core *engine.Ake, req []byte) error
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

// Note := there's no effect if esk, epk, and nonce have already been set
func (s *Server) Initialize(scalar group.Scalar, nonce []byte) {
	nonce = s.Ake.Initialize(scalar, nonce)
	if s.NonceS == nil {
		s.NonceS = nonce
	}
}

func (s *Server) Response(sk, pku, req, serverInfo []byte) (encKe2 []byte, err error) {
	s.Initialize(nil, nil)
	return s.response(s.Ake, s.Metadata, sk, pku, req, serverInfo)
}

func (s *Server) Finalize(req []byte) error {
	return s.finalize(s.Ake, req)
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
