package ake

import (
	"fmt"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

type Server struct {
	*Ake

	ClientMacKey []byte
	Transcript3  []byte
}

// Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (s *Server) Initialize(scalar group.Scalar, nonce []byte, nonceLen int) {
	nonce = s.Ake.Initialize(scalar, nonce, nonceLen)
	if s.NonceS == nil {
		s.NonceS = nonce
	}
}

func (s *Server) Response(ids, sk, idu, pku, serverInfo []byte, ke1 *message.KE1, response *message.CredentialResponse) (*message.KE2, error) {
	ikm, err := s.k3dh(sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	nonce := s.NonceS

	keys := DeriveKeys(s.Hash, tag3DH, idu, ke1.NonceU, ids, nonce, ikm)

	var einfo []byte
	if len(serverInfo) != 0 {
		pad := s.Hash.HKDFExpand(keys.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	transcript2 := utils.Concatenate(0, ke1.CredentialRequest.Serialize(), ke1.NonceU, internal.EncodeVector(ke1.ClientInfo), ke1.EpkU,
		response.Serialize(), nonce, s.Epk.Bytes(), internal.EncodeVector(einfo))
	ht := s.Hash.Hash(0, transcript2)
	mac := s.Hmac(ht, keys.ServerMac)

	s.Keys = keys
	s.ClientMacKey = keys.ClientMac
	s.SessionSecret = keys.SessionSecret
	s.Transcript3 = s.Hash.Hash(0, utils.Concatenate(0, transcript2, mac))

	return &message.KE2{
		NonceS: nonce,
		EpkS:   s.Epk.Bytes(),
		Einfo:  einfo,
		Mac:    mac,
	}, nil
}

func (s *Server) Finalize(kex *message.KE3) error {
	if !s.checkHmac(s.Transcript3, s.ClientMacKey, kex.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}

func (s *Server) k3dh(sk, epku, pku []byte) ([]byte, error) {
	sks, err := s.NewScalar().Decode(sk)
	if err != nil {
		return nil, fmt.Errorf("sk : %w", err)
	}

	epk, err := s.NewElement().Decode(epku)
	if err != nil {
		return nil, fmt.Errorf("epku : %w", err)
	}

	gpk, err := s.NewElement().Decode(pku)
	if err != nil {
		return nil, fmt.Errorf("pku : %w", err)
	}

	e1 := epk.Mult(s.Esk)
	e2 := epk.Mult(sks)
	e3 := gpk.Mult(s.Esk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes()), nil
}
