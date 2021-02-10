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
	*Metadata
}

// Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (s *Server) Initialize(scalar group.Scalar, nonce []byte) {
	nonce = s.Ake.Initialize(scalar, nonce)
	if s.NonceS == nil {
		s.NonceS = nonce
	}
}

func (s *Server) Response(sk, pku, serverInfo []byte, kex *message.KE1) (*message.KE2, error) {
	s.Initialize(nil, nil)

	s.Metadata.ClientInfo = kex.ClientInfo

	ikm, err := serverK3dh(s.Ake, sk, kex.EpkU, pku)
	if err != nil {
		return nil, err
	}

	s.DeriveKeys(s.Metadata, tag3DH, kex.NonceU, s.NonceS, ikm)

	var einfo []byte
	if len(serverInfo) != 0 {
		pad := s.Hash.HKDFExpand(s.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	s.Transcript2 = utils.Concatenate(0, s.Metadata.CredentialRequest, kex.NonceU, internal.EncodeVector(s.Metadata.ClientInfo), kex.EpkU,
		s.Metadata.CredentialResponse, s.NonceS, s.Epk.Bytes(), internal.EncodeVector(einfo))
	ht := s.Hash.Hash(0, s.Transcript2)
	s.Ke2Mac = s.Hmac(ht, s.ServerMac)

	return &message.KE2{
		NonceS: s.NonceS,
		EpkS:   s.Epk.Bytes(),
		Einfo:  einfo,
		Mac:    s.Ke2Mac,
	}, nil
}

func (s *Server) Finalize(kex *message.KE3) error {
	s.Transcript3 = s.Hash.Hash(0, utils.Concatenate(0, s.Transcript2, s.Ke2Mac))

	if !s.checkHmac(s.Transcript3, s.ClientMac, kex.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}

func serverK3dh(a *Ake, sk, epku, pku []byte) ([]byte, error) {
	sks, err := a.NewScalar().Decode(sk)
	if err != nil {
		return nil, fmt.Errorf("sk : %w", err)
	}

	epk, err := a.NewElement().Decode(epku)
	if err != nil {
		return nil, fmt.Errorf("epku : %w", err)
	}

	gpk, err := a.NewElement().Decode(pku)
	if err != nil {
		return nil, fmt.Errorf("pku : %w", err)
	}

	e1 := epk.Mult(a.Esk)
	e2 := epk.Mult(sks)
	e3 := gpk.Mult(a.Esk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes()), nil
}
