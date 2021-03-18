package ake

import (
	"crypto/hmac"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Server struct {
	*Ake

	NonceS    []byte // todo: only useful in testing, to force value
	ClientMac []byte
}

func NewServer(id ciphersuite.Identifier, kdf *internal.KDF, mac *internal.Mac, h *internal.Hash) *Server {
	return &Server{
		Ake: &Ake{
			Identifier: id,
			Group:      id.Get(nil),
			KDF:        kdf,
			Mac:        mac,
			Hash:       h,
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

func (s *Server) Response(ids, sk, idu, pku, serverInfo []byte, ke1 *message.KE1, response *message.CredentialResponse) (*message.KE2, error) {
	s.Initialize(nil, nil, 32)

	ikm, err := s.ikm(sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	nonce := s.NonceS
	transcriptHasher := s.Hash.H
	newInfo(transcriptHasher, ke1, idu, ids, response.Serialize(), nonce, s.Epk.Bytes())
	keys := deriveKeys(s.KDF, ikm, transcriptHasher.Sum(nil))
	var einfo []byte

	if len(serverInfo) != 0 {
		pad := s.Expand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	_, _ = transcriptHasher.Write(internal.EncodeVector(einfo))
	transcript2 := transcriptHasher.Sum(nil)
	mac := s.MAC(keys.ServerMacKey, transcript2)

	s.Keys = keys
	s.SessionSecret = keys.SessionSecret
	_, _ = transcriptHasher.Write(mac)
	transcript3 := transcriptHasher.Sum(nil)
	s.ClientMac = s.MAC(keys.ClientMacKey, transcript3)

	return &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               internal.SerializePoint(s.Epk, s.Identifier),
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

func (s *Server) Finalize(kex *message.KE3) error {
	if !hmac.Equal(s.ClientMac, kex.Mac) {
		return ErrAkeInvalidClientMac
	}

	return nil
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}
