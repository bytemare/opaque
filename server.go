package opaque

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/internal/server"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Server struct {
	server *server.Server
}

func NewServer(ciphersuite voprf.Ciphersuite, h hash.Identifier, k ake.Identifier, oprfKey, akeSecretKey, akePubKey []byte) *Server {
	return &Server{server: server.NewServer(ciphersuite, h, k, oprfKey, akeSecretKey, akePubKey)}
}

func (s *Server) RegistrationResponse(req *message.RegistrationRequest, enc encoding.Encoding) (*message.RegistrationResponse, error) {
	evaluation, err := s.server.Oprf.Evaluate(req.Data)
	if err != nil {
		return nil, err
	}

	z, err := evaluation.Encode(enc)
	if err != nil {
		return nil, err
	}

	return &message.RegistrationResponse{
		Data: z,
		Pks:  s.server.AkePubKey,
	}, nil
}

func (s *Server) RegistrationFinalize(username, uuid, ids []byte, p *Parameters, up *message.RegistrationUpload, enc encoding.Encoding) (*UserRecord, *AkeRecord, error) {
	// todo : this is test only
	ku := s.server.Oprf.PrivateKey()
	ar := s.GetAkeRecord()

	env, err := up.Envelope.Encode(enc)
	if err != nil {
		return nil, nil, err
	}

	return NewUserRecord(username, uuid, up.Pku, env, ids, ku, ar.ID, p, up.Envelope.Contents.Mode), ar, nil
}

func (s *Server) GetAkeRecord() *AkeRecord {
	return &AkeRecord{
		ID:        utils.RandomBytes(32),
		Ake:       s.server.Ake.Identifier(),
		Group:     s.server.Oprf.Ciphersuite().Group(),
		Hash:      s.server.Ake.Hash.Identifier(),
		SecretKey: s.server.Ake.PrivateKey(),
		PublicKey: s.server.AkePubKey,
	}
}

func (s *Server) AuthenticationResponse(req *message.ClientInit, env *envelope.Envelope, creds message.Credentials, info1, info2, pku []byte, enc encoding.Encoding) (*message.ServerResponse, error) {
	credResp, ke2, einfo2, err := s.server.AuthenticationResponse(req, env, creds, info1, info2, pku, enc)
	if err != nil {
		return nil, err
	}

	return &message.ServerResponse{
		Cresp:  *credResp,
		KE2:    ke2,
		EInfo2: einfo2,
	}, nil
}

func (s *Server) AuthenticationFinalize(req *message.ClientFinish, enc encoding.Encoding) error {
	return s.server.Ake.Finalize(req.KE3, enc)
}

func (s *Server) SessionKey() []byte {
	return s.server.Ake.SessionKey()
}
