package ake

import (
	"fmt"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake/sigmai"
	"github.com/bytemare/opaque/internal"
)

type Server struct {
	id Identifier
	*Ake
	*Metadata
}

func (s *Server) Identifier() Identifier {
	return s.id
}

// Note := there's no effect if esk, epk, and nonce have already been set
func (s *Server) Initialize(scalar group.Scalar, nonce []byte) {
	nonce = s.Ake.Initialize(scalar, nonce)
	if s.NonceS == nil {
		s.NonceS = nonce
	}
}

func (s *Server) Response(sk, pku, req, serverInfo []byte) (encKe2 []byte, err error) {
	s.Initialize(nil, nil)
	ke1, err := DeserializeKe1(req, s.Ake.NonceLen, s.Ake.Group.ElementLength())
	if err != nil {
		return nil, err
	}

	s.Metadata.ClientInfo = ke1.ClientInfo

	ikm, err := serverK3dh(s.Ake, sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	s.Ake.DeriveKeys(s.Metadata, tag3DH, ke1.NonceU, s.Ake.NonceS, ikm)

	var einfo []byte
	if len(serverInfo) != 0 {
		pad := s.Ake.Hash.HKDFExpand(s.Ake.HandshakeEncryptKey, []byte(encryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	s.Ake.Transcript2 = utils.Concatenate(0, s.Metadata.CredReq, ke1.NonceU, internal.EncodeVector(s.Metadata.ClientInfo), ke1.EpkU, s.Metadata.CredResp, s.Ake.NonceS, s.Ake.Epk.Bytes(), internal.EncodeVector(einfo))

	return Ke2{
		NonceS: s.Ake.NonceS,
		EpkS:   s.Ake.Epk.Bytes(),
		Einfo:  einfo,
		Mac:    s.Ake.Hmac(s.Ake.Transcript2, s.Ake.ServerMac),
	}.Serialize(), nil
}

func (s *Server) Finalize(req []byte) error {
	ke3, err := DeserializeKe3(req, s.Ake.Hash.OutputSize())
	if err != nil {
		return err
	}

	s.Ake.Transcript3 = utils.Concatenate(0, s.Ake.Transcript2)

	if !checkHmac(s.Ake.Hash, s.Ake.Transcript3, s.Ake.ClientMac, ke3.Mac) {
		return internal.ErrAkeInvalidClientMac
	}

	return nil
}

func (s *Server) KeyGen() (sk, pk []byte) {
	switch s.Identifier() {
	case SigmaI:
		return sigmai.KeyGen()
	case TripleDH:
		return KeyGen(s.Group)
	default:
		panic("invalid")
	}
}

func (s *Server) SessionKey() []byte {
	return s.SessionSecret
}


func serverK3dh(c *Ake, sk, epku, pku []byte) ([]byte, error) {
	sks, err := c.NewScalar().Decode(sk)
	if err != nil {
		return nil, fmt.Errorf("sk : %w", err)
	}

	epk, err := c.NewElement().Decode(epku)
	if err != nil {
		return nil, fmt.Errorf("epku : %w", err)
	}

	gpk, err := c.NewElement().Decode(pku)
	if err != nil {
		return nil, fmt.Errorf("pku : %w", err)
	}

	e1 := epk.Mult(c.Esk)
	e2 := epk.Mult(sks)
	e3 := gpk.Mult(c.Esk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes()), nil
}
