package opaque

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/parameters"
	"github.com/bytemare/opaque/message"
)

type Server struct {
	*parameters.Parameters
	Ake  *ake.Server
}

func NewServer(p *Parameters) *Server {
	ip := &parameters.Parameters{
		OprfCiphersuite: p.OprfCiphersuite,
		KDF:             &internal.KDF{H: p.KDF.Get()},
		MAC:             &internal.Mac{Hash: p.MAC.Get()},
		Hash:            &internal.Hash{H: p.Hash.Get()},
		MHF:             &internal.MHF{MHF: p.MHF.Get()},
		AKEGroup:        p.AKEGroup,
		NonceLen:        p.NonceLen,
		Deserializer: p.MessageDeserializer(),
	}

	return &Server{
		Parameters: ip,
		Ake:          ake.NewServer(ip),
	}
}

func (s *Server) evaluate(seed, blinded []byte) (element, k []byte, err error) {
	oprf, err := s.OprfCiphersuite.Server(nil)
	if err != nil {
		return nil, nil, err
	}

	ku := oprf.HashToScalar(seed)
	oprf, err = s.OprfCiphersuite.Server(ku.Bytes())
	if err != nil {
		return nil, nil, err
	}

	evaluation, err := oprf.Evaluate(blinded)
	if err != nil {
		return nil, nil, err
	}

	return evaluation.Elements[0], oprf.PrivateKey(), nil
}

func (s *Server) RegistrationResponse(req *message.RegistrationRequest, pks []byte, id CredentialIdentifier, oprfSeed []byte) (*message.RegistrationResponse, []byte, error) {
	seed := s.KDF.Expand(oprfSeed, internal.Concat(id, internal.OprfKey), internal.ScalarLength(s.OprfCiphersuite.Group()))

	z, ku, err := s.evaluate(seed, req.Data)
	if err != nil {
		return nil, nil, err
	}

	return &message.RegistrationResponse{
		Data: internal.PadPoint(z, s.OprfCiphersuite.Group()),
		Pks:  pks,
	}, ku, nil
}

func (s *Server) CredentialResponse(req *message.CredentialRequest, pks []byte, record *message.RegistrationUpload, id CredentialIdentifier, oprfSeed, maskingNonce []byte) (*message.CredentialResponse, error) {
	seed := s.KDF.Expand(oprfSeed, internal.Concat(id, internal.OprfKey), internal.ScalarLength(s.OprfCiphersuite.Group()))

	z, _, err := s.evaluate(seed, req.Data)
	if err != nil {
		return nil, err
	}

	//maskingNonce := utils.RandomBytes(32) // todo testing
	env := record.Envelope
	crPad := s.KDF.Expand(record.MaskingKey, utils.Concatenate(len(maskingNonce)+len([]byte(internal.TagCredentialResponsePad)), maskingNonce, []byte(internal.TagCredentialResponsePad)), len(pks)+len(env))
	clear := append(pks, env...)
	maskedResponse := internal.Xor(crPad, clear)

	return &message.CredentialResponse{
		Data:           internal.PadPoint(z, s.OprfCiphersuite.Group()),
		MaskingNonce:   maskingNonce,
		MaskedResponse: maskedResponse,
	}, nil
}

func (s *Server) AuthenticationResponse(ke1 *message.KE1, serverInfo, sks, pks []byte, upload *message.RegistrationUpload, creds *envelope.Credentials, id CredentialIdentifier, oprfSeed []byte) (*message.KE2, error) {
	response, err := s.CredentialResponse(ke1.CredentialRequest, pks, upload, id, oprfSeed, creds.MaskingNonce)
	if err != nil {
		return nil, err
	}

	if creds.Idc == nil {
		creds.Idc = upload.PublicKey
	}

	if creds.Ids == nil {
		creds.Ids = pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke2, err := s.Ake.Response(creds.Ids, sks, creds.Idc, upload.PublicKey, serverInfo, ke1, response)
	if err != nil {
		return nil, err
	}

	return ke2, nil
}

func (s *Server) AuthenticationFinalize(ke3 *message.KE3) error {
	return s.Ake.Finalize(ke3)
}

func (s *Server) KeyGen() (sk, pk []byte) {
	return ake.KeyGen(s.Ake.AKEGroup)
}

func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}
