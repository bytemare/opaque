package opaque

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

type Server struct {
	ake       *ake.Server
	oprf      *voprf.Server
	akePubKey []byte
	nonceLen  int
	meta *internal.Metadata
}

func NewServer(ciphersuite voprf.Ciphersuite, h hash.Identifier, k ake.Identifier, oprfKey, akeSecretKey, akePubKey []byte) *Server {
	oprf, err := ciphersuite.Server(oprfKey)
	if err != nil {
		panic(err)
	}

	a := k.Server(ciphersuite.Group().Get(nil), h.Get(), akeSecretKey)

	return &Server{
		ake:       a,
		oprf:      oprf,
		akePubKey: akePubKey,
		nonceLen:  32,
		meta: &internal.Metadata{},
	}
}

func (s *Server) evaluate(blinded []byte) *voprf.Evaluation {
	evaluation, err := s.oprf.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	return evaluation
}

func (s *Server) serverMetaData(creq *CredentialRequest, cresp *CredentialResponse, pku, idu, ids, info1 []byte, enc encoding.Encoding) {
	s.meta.IDu = idu
	if s.meta.IDu == nil {
		s.meta.IDu = pku
	}

	s.meta.IDs = ids
	if s.meta.IDs == nil {
		s.meta.IDs = s.akePubKey
	}

	encCreq, err := enc.Encode(creq)
	if err != nil {
		panic(err)
	}

	encCresp, err := enc.Encode(cresp)
	if err != nil {
		panic(err)
	}

	s.meta.CredReq = encCreq
	s.meta.CredResp = encCresp
	s.meta.IDu = idu
	s.meta.IDs = ids
	s.meta.Info1 = info1
}