package ake

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encode"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var errAkeInvalidClientMac = errors.New("invalid client mac")

// Server h
type Server struct {
	*ake
	ClientMac []byte

	// testing: integrated to support testing, to force values.
	Esk    group.Scalar
	NonceS []byte
}

func NewServer(parameters *internal.Parameters) *Server {
	return &Server{
		ake: &ake{
			Parameters: parameters,
			Group:      parameters.AKEGroup.Get(nil),
		},
	}
}

// SetValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func (s *Server) SetValues(esk group.Scalar, nonce []byte, nonceLen int) group.Element {
	es, p, nonce := s.ake.setValues(esk, nonce, nonceLen)
	s.Esk = es

	if s.NonceS == nil {
		s.NonceS = nonce
	}

	return p
}

func (s *Server) ikm(sks, epku, pku []byte) ([]byte, error) {
	sk, epk, gpk, err := decodeKeys(s.Group, sks, epku, pku)
	if err != nil {
		return nil, err
	}

	return k3dh(epk, s.Esk, epk, sk, gpk, s.Esk), nil
}

// Response produces a 3DH server response message.
func (s *Server) Response(ids, sk, idu, pku, serverInfo []byte, ke1 *message.KE1, response *cred.CredentialResponse) (*message.KE2, error) {
	epk := s.SetValues(nil, nil, 32)

	ikm, err := s.ikm(sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	nonce := s.NonceS
	transcriptHasher := s.Hash
	newInfo(transcriptHasher, ke1, idu, ids, response.Serialize(), nonce, epk.Bytes())
	keys, sessionSecret := deriveKeys(s.KDF, ikm, transcriptHasher.Sum())

	var einfo []byte

	if len(serverInfo) != 0 {
		pad := s.KDF.Expand(keys.handshakeEncryptKey, []byte(internal.EncryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	transcriptHasher.Write(encode.EncodeVector(einfo))
	transcript2 := transcriptHasher.Sum()
	mac := s.MAC.MAC(keys.serverMacKey, transcript2)

	s.SessionSecret = sessionSecret
	transcriptHasher.Write(mac)
	transcript3 := transcriptHasher.Sum()
	s.ClientMac = s.MAC.MAC(keys.clientMacKey, transcript3)

	return &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               internal.SerializePoint(epk, s.AKEGroup),
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

// Finalize verifies the authentication tag contained in ke3.
func (s *Server) Finalize(ke3 *message.KE3) error {
	if !hmac.Equal(s.ClientMac, ke3.Mac) {
		return errAkeInvalidClientMac
	}

	return nil
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}
