package ake

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/internal"
)

type (
	response       func(core *internal.Core, m *internal.Metadata, nonceLen int, sk, pku, req, info2 []byte, enc encoding.Encoding) ([]byte, []byte, error)
	serverFinalize func(core *internal.Core, req []byte, enc encoding.Encoding) error
)

type Server struct {
	id Identifier
	*internal.Core
	sk []byte
	response
	finalize serverFinalize
}

func (s *Server) Identifier() Identifier {
	return s.id
}

func (s *Server) PrivateKey() []byte {
	return s.sk
}

func (s *Server) Response(m *internal.Metadata, nonceLen int, pku, req, info2 []byte, enc encoding.Encoding) (encKe2, einfo2 []byte, err error) {
	return s.response(s.Core, m, nonceLen, s.sk, pku, req, info2, enc)
}

func (s *Server) Finalize(req []byte, enc encoding.Encoding) error {
	return s.finalize(s.Core, req, enc)
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}
