// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

// Server exposes the server's AKE functions and holds its state.
type Server struct {
	clientMac     []byte
	sessionSecret []byte

	// testing: integrated to support testing, to force values.
	esk    group.Scalar
	nonceS []byte
}

func NewServer() *Server {
	return &Server{}
}

// SetValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func (s *Server) SetValues(p *internal.Parameters, esk group.Scalar, nonce []byte, nonceLen int) group.Element {
	es, nonce := setValues(p, esk, nonce, nonceLen)
	if s.esk == nil || (esk != nil && s.esk != es) {
		s.esk = es
	}

	if s.nonceS == nil {
		s.nonceS = nonce
	}

	return p.AKEGroup.Get(nil).Base().Mult(s.esk)
}

func (s *Server) ikm(g group.Group, sks, epku, pku []byte) ([]byte, error) {
	sk, epk, gpk, err := decodeKeys(g, sks, epku, pku)
	if err != nil {
		return nil, err
	}

	return k3dh(epk, s.esk, epk, sk, gpk, s.esk), nil
}

// Response produces a 3DH server response message.
func (s *Server) Response(p *internal.Parameters, ids, sk, idu, pku, serverInfo []byte,
	ke1 *message.KE1, response *cred.CredentialResponse) (*message.KE2, error) {
	epk := s.SetValues(p, nil, nil, 32)

	g := p.AKEGroup.Get(nil)

	ikm, err := s.ikm(g, sk, ke1.EpkU, pku)
	if err != nil {
		return nil, err
	}

	nonce := s.nonceS
	transcriptHasher := p.Hash
	newInfo(transcriptHasher, ke1, idu, ids, response.Serialize(), nonce, epk.Bytes())
	keys, sessionSecret := deriveKeys(p.KDF, ikm, transcriptHasher.Sum())

	var einfo []byte

	if len(serverInfo) != 0 {
		pad := p.KDF.Expand(keys.handshakeEncryptKey, []byte(internal.EncryptionTag), len(serverInfo))
		einfo = internal.Xor(pad, serverInfo)
	}

	transcriptHasher.Write(encoding.EncodeVector(einfo))
	transcript2 := transcriptHasher.Sum()
	mac := p.MAC.MAC(keys.serverMacKey, transcript2)

	transcriptHasher.Write(mac)
	transcript3 := transcriptHasher.Sum()
	s.clientMac = p.MAC.MAC(keys.clientMacKey, transcript3)
	s.sessionSecret = sessionSecret

	return &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               internal.SerializePoint(epk, p.AKEGroup),
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

// Finalize verifies the authentication tag contained in ke3.
func (s *Server) Finalize(p *internal.Parameters, ke3 *message.KE3) bool {
	return p.MAC.Equal(s.clientMac, ke3.Mac)
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (s *Server) SessionKey() []byte {
	return s.sessionSecret
}
