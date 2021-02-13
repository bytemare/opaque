package ake

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Server struct {
	*Ake

	NonceS       []byte // todo: only useful in testing, to force value
	ClientMacKey []byte
	Transcript3  []byte
}

func NewServer(g group.Group, h hash.Identifier) *Server {
	return &Server{
		Ake: &Ake{
			Group: g,
			Hash:  h.Get(),
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
	ikm, err := s.ikm(sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	nonce := s.NonceS
	keys := deriveKeys(s.Hash, tag3DH, idu, ke1.NonceU, ids, nonce, ikm)

	var einfo []byte
	if len(serverInfo) != 0 {
		pad := s.Hash.HKDFExpand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	transcript2 := utils.Concatenate(0, ke1.Serialize(),
		response.Serialize(), nonce, s.Epk.Bytes(), internal.EncodeVector(einfo))
	mac := s.Hmac(transcript2, keys.ServerMac)

	s.Keys = keys
	s.ClientMacKey = keys.ClientMac
	s.SessionSecret = keys.SessionSecret
	s.Transcript3 = utils.Concatenate(0, transcript2, mac)

	return &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               s.Epk.Bytes(),
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

func (s *Server) Finalize(kex *message.KE3) error {
	if !s.checkHmac(s.Transcript3, s.ClientMacKey, kex.Mac) {
		return ErrAkeInvalidClientMac
	}

	return nil
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}
