package opaque

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type CredentialFile struct {
	Pkc        []byte             `json:"pku"`
	MaskingKey []byte             `json:"msk"`
	Envelope   *envelope.Envelope `json:"envU"`
}

type Server struct {
	oprf voprf.Ciphersuite
	kdf  *internal.KDF
	Ake  *ake.Server
	*message.Deserializer
}

func NewServer(p *Parameters) *Server {
	k := &internal.KDF{H: p.KDF.Get()}
	mac2 := &internal.Mac{Hash: p.MAC.Get()}
	h2 := &internal.Hash{H: p.Hash.Get()}
	return &Server{
		oprf:         p.OprfCiphersuite,
		kdf:          k,
		Ake:          ake.NewServer(p.Group, k, mac2, h2),
		Deserializer: p.MessageDeserializer(),
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

func (s *Server) RegistrationResponse(req *message.RegistrationRequest, pks []byte, id CredentialIdentifier, oprfSeed []byte) (*message.RegistrationResponse, error) {
	x := s.kdf.Expand(oprfSeed, internal.ExtendNonce(id, "OprfKey"), internal.ScalarLength(s.oprf.Group()))
	ku := DeriveSecretKey(s.oprf.Group(), x)

	z, _, err := s.evaluate(ku.Bytes(), req.Data)
	if err != nil {
		return nil, err
	}

	return &message.RegistrationResponse{
		Data: internal.PadPoint(z, s.oprf.Group()),
		Pks:  pks,
	}, nil
}

const (
	credentialResponsePad = "CredentialResponsePad"
	oprfKey               = "OprfKey"
)

func (s *Server) CredentialResponse(req *message.CredentialRequest, pks []byte, file *CredentialFile, id CredentialIdentifier, oprfSeed []byte) (*message.CredentialResponse, error) {
	x := s.kdf.Expand(oprfSeed, internal.ExtendNonce(id, oprfKey), internal.ScalarLength(s.oprf.Group()))
	ku := DeriveSecretKey(s.oprf.Group(), x)

	z, _, err := s.evaluate(ku.Bytes(), req.Data)
	if err != nil {
		return nil, err
	}

	maskingNonce := utils.RandomBytes(32)
	// todo: find way to use lengths here
	env := file.Envelope.Serialize()
	crPad := s.kdf.Expand(file.MaskingKey, utils.Concatenate(len(maskingNonce)+len([]byte(credentialResponsePad)), maskingNonce, []byte("CredentialResponsePad")), len(pks)+len(env))
	clear := append(pks, env...)
	maskedResponse := internal.Xor(crPad, clear)

	return &message.CredentialResponse{
		Data:           internal.PadPoint(z, s.oprf.Group()),
		MaskingNonce:   maskingNonce,
		MaskedResponse: maskedResponse,
	}, nil
}

func (s *Server) AuthenticationResponse(ke1 *message.KE1, serverInfo, sks, pks []byte, credFile *CredentialFile, creds *envelope.Credentials, id CredentialIdentifier, oprfSeed []byte) (*message.KE2, error) {
	response, err := s.CredentialResponse(ke1.CredentialRequest, pks, credFile, id, oprfSeed)
	if err != nil {
		return nil, err
	}

	if creds.Idc == nil {
		creds.Idc = credFile.Pkc
	}

	if creds.Ids == nil {
		creds.Ids = pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke2, err := s.Ake.Response(creds.Ids, sks, creds.Idc, credFile.Pkc, serverInfo, ke1, response)
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
