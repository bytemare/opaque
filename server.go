package opaque

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type CredentialFile struct {
	Ku       []byte            `json:"ku"`
	Pku      []byte            `json:"pku"`
	Envelope *envelope.Envelope `json:"envU"`
}

type Server struct {
	oprf voprf.Ciphersuite
	Ake  *ake.Server
}

func NewServer(suite voprf.Ciphersuite, h hash.Identifier, k ake.Identifier, nonceLen int) *Server {
	return &Server{
		oprf: suite,
		Ake:  k.Server(suite.Group().Get(nil), h.Get(), nonceLen),
	}
}

func (s *Server) evaluate(ku, blinded []byte) (element, k []byte, err error) {
	oprf, err := s.oprf.Server(ku)
	if err != nil {
		return nil, nil, err
	}

	evaluation, err := oprf.Evaluate(blinded)
	if err != nil {
		return nil, nil, err
	}

	return evaluation.Elements[0], oprf.PrivateKey(), nil
}

func (s *Server) RegistrationResponse(req *message.RegistrationRequest, pks, ku []byte) (*message.RegistrationResponse, []byte, error) {
	z, ku, err := s.evaluate(ku, req.Data)
	if err != nil {
		return nil, ku, err
	}

	return &message.RegistrationResponse{
		Data: z,
		Pks:  pks,
	}, ku, nil
}

func (s *Server) CredentialResponse(req *message.CredentialRequest, pks []byte, file *CredentialFile) (*message.CredentialResponse, error) {
	z, _, err := s.evaluate(file.Ku, req.Data)
	if err != nil {
		return nil, err
	}

	return &message.CredentialResponse{
		Data:     z,
		Pks:      pks,
		Envelope: file.Envelope,
	}, nil
}

func (s *Server) AuthenticationResponse(req *message.ClientInit, serverInfo []byte, credFile *CredentialFile, creds *envelope.Credentials) (*message.ServerResponse, error) {
	response, err := s.CredentialResponse(req.Creq, creds.Pk, credFile)
	if err != nil {
		return nil, err
	}

	s.Ake.Metadata.Init(req.Creq, nil)
	s.Ake.Metadata.Fill(credFile.Envelope.Contents.Mode, response, credFile.Pku, creds.Pk, creds)

	s.Ake.Initialize(nil, nil)
	ke2, err := s.Ake.Response(creds.Sk, credFile.Pku, req.KE1, serverInfo)
	if err != nil {
		return nil, err
	}

	return &message.ServerResponse{
		Cresp: response,
		KE2:   ke2,
	}, nil
}

func (s *Server) AuthenticationFinalize(req *message.ClientFinish) error {
	return s.Ake.Finalize(req.KE3)
}

func (s *Server) KeyGen() (sk, pk []byte) {
	return s.Ake.KeyGen()
}

func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}
