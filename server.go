package opaque

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type CredentialFile struct {
	Ku       []byte            `json:"ku"`
	Pku      []byte            `json:"pku"`
	Envelope envelope.Envelope `json:"envU"`
}

type Server struct {
	ku   []byte
	oprf voprf.Ciphersuite
	Ake  *ake.Server
}

func NewServer(suite voprf.Ciphersuite, h hash.Identifier, k ake.Identifier, g ciphersuite.Identifier, nonceLen int) *Server {
	return &Server{
		ku:   nil,
		oprf: suite,
		Ake:  k.Server(g.Get(nil), h.Get(), nonceLen),
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

func (s *Server) RegistrationResponse(req *message.RegistrationRequest, pks []byte) (*message.RegistrationResponse, error) {
	z, ku, err := s.evaluate(nil, req.Data)
	if err != nil {
		return nil, err
	}

	s.ku = ku

	return &message.RegistrationResponse{
		Data: z,
		Pks:  pks,
	}, nil
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

func (s *Server) serverMetaData(mode envelope.Mode, creq *message.CredentialRequest, cresp *message.CredentialResponse, creds *envelope.Credentials, info1, pku []byte, enc encoding.Encoding) error {
	err := s.Ake.Metadata.Init(creq, info1, enc)
	if err != nil {
		return err
	}

	if err := s.Ake.Metadata.Fill(mode, cresp, pku, creds.Pk, creds, enc); err != nil {
		return err
	}

	return nil
}

func (s *Server) AuthenticationResponse(req *message.ClientInit, info1, info2 []byte, credFile *CredentialFile, creds *envelope.Credentials, enc encoding.Encoding) (*message.ServerResponse, error) {
	response, err := s.CredentialResponse(&req.Creq, creds.Pk, credFile)
	if err != nil {
		return nil, err
	}

	if err := s.serverMetaData(credFile.Envelope.Contents.Mode, &req.Creq, response, creds, info1, credFile.Pku, enc); err != nil {
		return nil, err
	}

	ke2, einfo2, err := s.Ake.Response(creds.Sk, credFile.Pku, req.KE1, info2, enc)
	if err != nil {
		return nil, err
	}

	return &message.ServerResponse{
		Cresp:  *response,
		KE2:    ke2,
		EInfo2: einfo2,
	}, nil
}

func (s *Server) AuthenticationFinalize(req *message.ClientFinish, enc encoding.Encoding) error {
	return s.Ake.Finalize(req.KE3, enc)
}

func (s *Server) OprfKey() []byte {
	return s.ku
}

func (s *Server) KeyGen() (sk, pk []byte) {
	return s.Ake.KeyGen()
}

func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}
