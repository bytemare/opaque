// Package opaque implements the OPAQUE PAKE protocol.
package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/core/envelope"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidClientMac = errors.New("failed to authenticate client: invalid client mac")

// Server represents an OPAQUE Server, exposing its functions and holding its state.
type Server struct {
	*internal.Parameters
	Ake *ake.Server
}

// NewServer returns a Server instantiation given the application Parameters.
func NewServer(p *Parameters) *Server {
	ip := p.toInternal()

	return &Server{
		Parameters: ip,
		Ake:        ake.NewServer(),
	}
}

// KeyGen returns a key pair in the AKE group.
func (s *Server) KeyGen() (sk, pk []byte) {
	return ake.KeyGen(s.AKEGroup)
}

func (s *Server) evaluate(seed, blinded []byte) (m, k []byte, err error) {
	oprf, err := s.OprfCiphersuite.Server(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("oprf server setup: %w", err)
	}

	ku := oprf.HashToScalar(seed)

	oprf, err = s.OprfCiphersuite.Server(ku.Bytes())
	if err != nil {
		return nil, nil, fmt.Errorf("oprf server setup with key: %w", err)
	}

	evaluation, err := oprf.Evaluate(blinded)
	if err != nil {
		return nil, nil, fmt.Errorf("oprf evaluation: %w", err)
	}

	return evaluation.Elements[0], oprf.PrivateKey(), nil
}

func (s *Server) oprfResponse(oprfSeed, id, element []byte) (m, k []byte, err error) {
	seed := s.KDF.Expand(oprfSeed, internal.Concat(id, internal.OprfKey), internal.ScalarLength[s.OprfCiphersuite.Group()])
	return s.evaluate(seed, element)
}

// RegistrationResponse returns a RegistrationResponse message to the input RegistrationRequest message and given identifiers.
func (s *Server) RegistrationResponse(req *message.RegistrationRequest, pks []byte, id CredentialIdentifier,
	oprfSeed []byte) (r *message.RegistrationResponse, ku []byte, err error) {
	z, ku, err := s.oprfResponse(oprfSeed, id, req.Data)
	if err != nil {
		return nil, nil, fmt.Errorf(" RegistrationResponse: %w", err)
	}

	return &message.RegistrationResponse{
		Data: internal.PadPoint(z, s.OprfCiphersuite.Group()),
		Pks:  pks,
	}, ku, nil
}

func (s *Server) credentialResponse(req *cred.CredentialRequest, pks []byte, record *message.RegistrationUpload,
	id CredentialIdentifier, oprfSeed, maskingNonce []byte) (*cred.CredentialResponse, error) {
	z, _, err := s.oprfResponse(oprfSeed, id, req.Data)
	if err != nil {
		return nil, fmt.Errorf("oprfResponse: %w", err)
	}

	// testing: integrated to support testing, to force values.
	if len(maskingNonce) == 0 {
		maskingNonce = utils.RandomBytes(32)
	}

	env := record.Envelope
	crPad := s.KDF.Expand(record.MaskingKey,
		internal.Concat(maskingNonce, internal.TagCredentialResponsePad),
		len(pks)+len(env))

	clear := append(pks, env...)

	maskedResponse := internal.Xor(crPad, clear)

	return &cred.CredentialResponse{
		Data:           internal.PadPoint(z, s.OprfCiphersuite.Group()),
		MaskingNonce:   maskingNonce,
		MaskedResponse: maskedResponse,
	}, nil
}

// AuthenticationInit responds to a KE1 message with a KE2 message given server credentials and client record.
func (s *Server) AuthenticationInit(ke1 *message.KE1, serverInfo, sks, pks []byte, upload *message.RegistrationUpload,
	creds *envelope.Credentials, id CredentialIdentifier, oprfSeed []byte) (*message.KE2, error) {
	response, err := s.credentialResponse(ke1.CredentialRequest, pks, upload, id, oprfSeed, creds.MaskingNonce)
	if err != nil {
		return nil, fmt.Errorf(" credentialResponse: %w", err)
	}

	if creds.Idc == nil {
		creds.Idc = upload.PublicKey
	}

	if creds.Ids == nil {
		creds.Ids = pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke2, err := s.Ake.Response(s.Parameters, creds.Ids, sks, creds.Idc, upload.PublicKey, serverInfo, ke1, response)
	if err != nil {
		return nil, fmt.Errorf(" AKE response: %w", err)
	}

	return ke2, nil
}

// AuthenticationFinalize returns an error if the KE3 received from the client holds an invalid mac, and nil if correct.
func (s *Server) AuthenticationFinalize(ke3 *message.KE3) error {
	if !s.Ake.Finalize(s.Parameters, ke3) {
		return errAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the session key if the previous calls to AuthenticationInit() and AuthenticationFinalize() were
// successful.
func (s *Server) SessionKey() []byte {
	return s.Ake.SessionKey()
}
