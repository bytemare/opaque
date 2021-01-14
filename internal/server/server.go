package server

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Server struct {
	Ake       *ake.Server
	Oprf      *voprf.Server
	AkePubKey []byte
	nonceLen  int
	meta      *internal.Metadata
}

func NewServer(ciphersuite voprf.Ciphersuite, h hash.Identifier, k ake.Identifier, oprfKey, akeSecretKey, akePubKey []byte) *Server {
	oprf, err := ciphersuite.Server(oprfKey)
	if err != nil {
		panic(err)
	}

	a := k.Server(ciphersuite.Group().Get(nil), h.Get(), akeSecretKey)

	return &Server{
		Ake:       a,
		Oprf:      oprf,
		AkePubKey: akePubKey,
		nonceLen:  32,
		meta:      &internal.Metadata{},
	}
}

func (s *Server) evaluate(blinded []byte) *voprf.Evaluation {
	evaluation, err := s.Oprf.Evaluate(blinded)
	if err != nil {
		panic(err)
	}

	return evaluation
}

func (s *Server) serverMetaData(creds message.Credentials, creq *message.CredentialRequest, cresp *message.CredentialResponse, info1, pku []byte, enc encoding.Encoding) {
	encCreq, err := enc.Encode(creq)
	if err != nil {
		panic(err)
	}

	s.meta.CredReq = encCreq

	if err := s.meta.Fill(creds, cresp, pku, enc); err != nil {
		panic(err)
	}
}
