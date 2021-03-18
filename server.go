package opaque

import (
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type CredentialFile struct {
	Ku       []byte             `json:"ku"`
	Pkc      []byte             `json:"pku"`
	Envelope *envelope.Envelope `json:"envU"`
}

type Server struct {
	oprf voprf.Ciphersuite
	Ake  *ake.Server
	*message.Deserializer
}

func NewServer(p *Parameters) *Server {
	k := &internal.KDF{Hash: p.KDF.Get()}
	mac2 := &internal.Mac{Hash: p.MAC.Get()}
	h2 := &internal.Hash{H: p.Hash.Get()}
	return &Server{
		oprf:         p.OprfCiphersuite,
		Ake:          ake.NewServer(p.Group, k, mac2, h2),
		Deserializer: p.Deserializer(),
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
		Data: internal.PadPoint(z, s.oprf.Group()),
		Pks:  pks,
	}, ku, nil
}

func (s *Server) CredentialResponse(req *message.CredentialRequest, pks []byte, file *CredentialFile) (*message.CredentialResponse, error) {
	z, _, err := s.evaluate(file.Ku, req.Data)
	if err != nil {
		return nil, err
	}

	return &message.CredentialResponse{
		Data:     internal.PadPoint(z, s.oprf.Group()),
		Pks:      pks,
		Pkc:      file.Pkc,
		Envelope: file.Envelope,
	}, nil
}

func (s *Server) AuthenticationResponse(ke1 *message.KE1, serverInfo []byte, credFile *CredentialFile, creds *envelope.Credentials) (*message.KE2, error) {
	response, err := s.CredentialResponse(ke1.CredentialRequest, creds.Pks, credFile)
	if err != nil {
		return nil, err
	}

	if creds.Idc == nil {
		creds.Idc = credFile.Pkc
	}

	if creds.Ids == nil {
		creds.Ids = creds.Pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke2, err := s.Ake.Response(creds.Ids, creds.Skx, creds.Idc, credFile.Pkc, serverInfo, ke1, response)
	if err != nil {
		return nil, err
	}

	return ke2, nil
}

func (s *Server) AuthenticationFinalize(ke3 *message.KE3) error {
	return s.Ake.Finalize(ke3)
}

func (s *Server) KeyGen() (sk, pk []byte) {
	return ake.KeyGen(s.Ake.Identifier)
}

func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}
