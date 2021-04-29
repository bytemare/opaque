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

type Server struct {
	*Ake
	ClientMac []byte
	NonceS    []byte // todo: only useful in testing, to force value
}

func NewServer(parameters *internal.Parameters) *Server {
	return &Server{
		Ake: &Ake{
			Parameters: parameters,
			Group:      parameters.AKEGroup.Get(nil),
			keys:       &keys{},
		},
	}
}

// todo: Only useful in testing, to force values
//  Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (s *Server) Initialize(esk group.Scalar, nonce []byte, nonceLen int) {
	nonce = s.Ake.Initialize(esk, nonce, nonceLen)

	if s.NonceS == nil {
		s.NonceS = nonce
	}
}

func (s *Server) ikm(sks, epku, pku []byte) ([]byte, error) {
	sk, epk, gpk, err := decodeKeys(s.Group, sks, epku, pku)
	if err != nil {
		return nil, err
	}

	return k3dh(epk, s.Esk, epk, sk, gpk, s.Esk), nil
}

func (s *Server) Response(ids, sk, idu, pku, serverInfo []byte, ke1 *message.KE1, response *cred.CredentialResponse) (*message.KE2, error) {
	s.Initialize(nil, nil, 32)

	ikm, err := s.ikm(sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	nonce := s.NonceS
	transcriptHasher := s.Hash.H
	newInfo(transcriptHasher, ke1, idu, ids, response.Serialize(), nonce, s.Epk.Bytes())
	keys, sessionSecret := deriveKeys(s.KDF, ikm, transcriptHasher.Sum(nil))

	var einfo []byte

	if len(serverInfo) != 0 {
		pad := s.KDF.Expand(keys.HandshakeEncryptKey, []byte(internal.EncryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	_, _ = transcriptHasher.Write(encode.EncodeVector(einfo))
	transcript2 := transcriptHasher.Sum(nil)
	mac := s.MAC.MAC(keys.ServerMacKey, transcript2)

	s.Keys = keys
	s.SessionSecret = sessionSecret
	_, _ = transcriptHasher.Write(mac)
	transcript3 := transcriptHasher.Sum(nil)
	s.ClientMac = s.MAC.MAC(keys.ClientMacKey, transcript3)

	return &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               internal.SerializePoint(s.Epk, s.AKEGroup),
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

func (s *Server) Finalize(ke3 *message.KE3) error {
	if !hmac.Equal(s.ClientMac, ke3.Mac) {
		return errAkeInvalidClientMac
	}

	return nil
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}
