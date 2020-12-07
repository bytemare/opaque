package threeDH

import (
	"crypto/hmac"
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup/group"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/new/ake"
	"github.com/bytemare/voprf"
)

type transcript struct {
	nonceU              []byte
	nonceS              []byte
	idu                 []byte
	ids                 []byte
	peerEphemeralPubKey []byte
	peerPubKey          []byte
}

type threeDH struct {
	transcript
	group.Group
	*hash.Hash
	esk, sk                  group.Scalar
	epk                      group.Element
	km2, km3                 []byte
	ke2, ke3                 []byte
	sessionSecret            []byte
	transcript2, transcript3 []byte
}

type Client struct {
	threeDH
	oprf *voprf.Client
}

func NewClient(suite voprf.Ciphersuite, g group.Group, h *hash.Hash) *Client {
	vc, err := suite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Client{
		threeDH: threeDH{Group: g, Hash: h},
		oprf:    vc,
	}
}

func (c *Client) Start(nonceLen int) *KE1 {
	c.esk = c.NewScalar().Random()
	c.epk = c.Base().Mult(c.esk)
	c.nonceU = utils.RandomBytes(nonceLen)

	return &KE1{
		NonceU: c.nonceU,
		EpkU:   c.epk.Bytes(),
	}
}

func (c *Client) k3dh(epks, pks group.Element) []byte {
	e1 := epks.Mult(c.esk)
	e2 := pks.Mult(c.esk)
	e3 := epks.Mult(c.sk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes())
}

func (c *Client) Finalize(credReqEnc, credRespEnc, sku, pks, idu, ids []byte, ke1 *KE1, ke2 *KE2, keyLen int) (*KE3, error) {
	sk, err := c.NewScalar().Decode(sku)
	if err != nil {
		return nil, err
	}
	c.sk = sk

	epks, err := c.NewElement().Decode(ke2.EpkS)
	if err != nil {
		return nil, err
	}

	gpks, err := c.NewElement().Decode(pks)
	if err != nil {
		return nil, err
	}

	c.transcript2 = utils.Concatenate(0, credReqEnc, ke1.NonceU, ke1.EpkU, credRespEnc, ke2.NonceS, ke2.EpkS)

	ikm := c.k3dh(epks, gpks)
	info := info([]byte("3DH keys"), ke1.NonceU, ke2.NonceS, idu, ids)
	handshakeSecret, sessionSecret := KeySchedule(c.Hash, ikm, info)
	c.km2, c.km3, c.ke2, c.ke3 = Keys(c.Hash, handshakeSecret, c.Hash.OutputSize(), keyLen)

	expectedHmac2 := c.Hmac(c.transcript2, c.km2)
	if !hmac.Equal(expectedHmac2, ke2.Mac) {
		return nil, errors.New("hmac on transcript 2 is invalid")
	}

	c.sessionSecret = sessionSecret
	c.transcript3 = c.transcript2

	return &KE3{Mac: c.Hmac(c.transcript3, c.km3)}, nil
}

func (c *Client) SessionSecret() []byte {
	return c.sessionSecret
}

type Server struct {
	threeDH
	oprf *voprf.Server
}

func NewServer(suite voprf.Ciphersuite, g group.Group, h *hash.Hash, privateKey []byte) *Server {
	vc, err := suite.Server(privateKey)
	if err != nil {
		panic(err)
	}

	sk, err := g.NewScalar().Decode(privateKey)
	if err != nil {
		panic(err)
	}

	return &Server{
		threeDH: threeDH{Group: g, Hash: h, sk: sk},
		oprf:    vc,
	}
}

func (s *Server) k3dh(epku, pku group.Element) []byte {
	e1 := epku.Mult(s.esk)
	e2 := epku.Mult(s.sk)
	e3 := pku.Mult(s.esk)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes())
}

func (s *Server) Response(keyLen, nonceLen int, credReqEnc, credRespEnc, idu, ids, pku []byte, req *KE1) (*KE2, error) {
	s.esk = s.NewScalar().Random()
	s.epk = s.Base().Mult(s.esk)
	s.nonceS = utils.RandomBytes(nonceLen)

	epku, err := s.NewElement().Decode(req.EpkU)
	if err != nil {
		return nil, err
	}

	gpku, err := s.NewElement().Decode(pku)
	if err != nil {
		return nil, err
	}

	ikm := s.k3dh(epku, gpku)
	info := info([]byte("3DH keys"), req.NonceU, s.nonceS, idu, ids)
	handshakeSecret, sessionSecret := KeySchedule(s.Hash, ikm, info)
	s.sessionSecret = sessionSecret
	s.km2, s.km3, s.ke2, s.ke3 = Keys(s.Hash, handshakeSecret, s.Hash.OutputSize(), keyLen)

	s.transcript2 = utils.Concatenate(0, credReqEnc, req.NonceU, req.EpkU, credRespEnc, s.nonceS, s.epk.Bytes())
	s.transcript3 = s.transcript2

	return &KE2{
		NonceS: s.nonceS,
		EpkS:   s.epk.Bytes(),
		Mac:    s.Hash.Hmac(s.transcript2, s.km2),
	}, nil
}

func (s *Server) Finalize(ke3 *KE3) bool {
	expectedHmac3 := s.Hmac(s.transcript3, s.km3)
	return hmac.Equal(expectedHmac3, ke3.Mac)
}

func (s *Server) SessionSecret() []byte {
	return s.sessionSecret
}

func KeySchedule(h *hash.Hash, ikm, info []byte) ([]byte, []byte) {
	handshakeSecret := ake.DeriveSecret(h, ikm, []byte("handshake secret"), info)
	sessionSecret := ake.DeriveSecret(h, ikm, []byte("session secret"), info)
	return handshakeSecret, sessionSecret
}

// key_length is the length of the key required for the AKE handshake encryption algorithm.
func Keys(h *hash.Hash, handshakeSecret []byte, hashLen, keyLen int) (km2, km3, ke2, ke3 []byte) {
	km2 = ake.HKDFExpandLabel(h, handshakeSecret, []byte("server mac"), []byte(""), hashLen)
	km3 = ake.HKDFExpandLabel(h, handshakeSecret, []byte("client mac"), []byte(""), hashLen)
	ke2 = ake.HKDFExpandLabel(h, handshakeSecret, []byte("server enc"), []byte(""), keyLen)
	ke3 = ake.HKDFExpandLabel(h, handshakeSecret, []byte("client enc"), []byte(""), keyLen)

	return
}

func lengthPrefixEncode(input []byte) []byte {
	return append(encoding.I2OSP2(uint(len(input))), input...)
}

func info(protoTag, nonceU, nonceS, idU, idS []byte) []byte {
	return utils.Concatenate(0, protoTag,
		lengthPrefixEncode(nonceU), lengthPrefixEncode(nonceS),
		lengthPrefixEncode(idU), lengthPrefixEncode(idS))
}
