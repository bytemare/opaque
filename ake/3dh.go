package ake

import (
	"errors"
	encoding2 "github.com/bytemare/opaque/internal/encoding"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

const (
	tag3DH        = "3DH"
	labelPrefix   = "OPAQUE "
	tagHandshake  = "handshake secret"
	tagSession    = "session secret"
	tagMacServer  = "server mac"
	tagMacClient  = "client mac"
	tagEncServer  = "handshake enc"
	encryptionTag = "encryption pad"
)

var (
	ErrAkeInvalidServerMac = errors.New("invalid server mac")
	ErrAkeInvalidClientMac = errors.New("invalid client mac")
)

func KeyGen(id ciphersuite.Identifier) (sk, pk []byte) {
	g := id.Get(nil)
	scalar := g.NewScalar().Random()
	publicKey := g.Base().Mult(scalar)

	return internal.SerializeScalar(scalar, id), internal.SerializePoint(publicKey, id)
}

type Keys struct {
	ServerMacKey, ClientMacKey []byte
	HandshakeSecret            []byte
	HandshakeEncryptKey        []byte
	SessionSecret              []byte
}

type keys struct {
	Esk   group.Scalar  // todo: only useful in testing (except for client), to force value
	Epk   group.Element // todo: only useful in testing, to force value
	*Keys               // todo: only useful in testing, to verify values
}

type Ake struct {
	*internal.Parameters
	group.Group
	SessionSecret []byte

	// Todo: For testing only, delete
	*keys
}

// todo: Only useful in testing, to force values
//  Note := there's no effect if esk, epk, and nonce have already been set in a previous call
func (a *Ake) Initialize(scalar group.Scalar, nonce []byte, nonceLen int) []byte {
	if a.Esk == nil {
		if scalar != nil {
			a.Esk = scalar
		} else {
			a.Esk = a.NewScalar().Random()
		}
	}

	a.Epk = a.Base().Mult(a.Esk)

	if len(nonce) != 0 {
		return nonce
	}

	return utils.RandomBytes(nonceLen)
}

func buildLabel(length int, label, context []byte) []byte {
	// todo : the encodings here assume every length fits into a 1-byte encoding
	return utils.Concatenate(0, encoding.I2OSP(length, 2), encoding2.EncodeVectorLen(append([]byte(labelPrefix), label...), 1), encoding2.EncodeVectorLen(context, 1))
}

func expand(h *internal.KDF, secret, hkdfLabel []byte) []byte {
	// todo : If len(label) > 12, the hash function might have additional iterations.
	return h.Expand(secret, hkdfLabel, h.Size())
}

func expandLabel(h *internal.KDF, secret, label, context []byte) []byte {
	hkdfLabel := buildLabel(h.Size(), label, context)
	return expand(h, secret, hkdfLabel)
}

func deriveSecret(h *internal.KDF, secret, label, context []byte) []byte {
	return expandLabel(h, secret, label, context)
}

func newInfo(h *hash.Hash, ke1 *message.KE1, idu, ids, response, nonceS, epks []byte) {
	cp := encoding2.EncodeVectorLen(idu, 2)
	sp := encoding2.EncodeVectorLen(ids, 2)
	_, _ = h.Write(utils.Concatenate(0, []byte(tag3DH), cp, ke1.Serialize(), sp, response, nonceS, epks))
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (*Keys, []byte) {
	prk := h.Extract(nil, ikm)
	k := &Keys{}
	k.HandshakeSecret = deriveSecret(h, prk, []byte(tagHandshake), context)
	sessionSecret := deriveSecret(h, prk, []byte(tagSession), context)
	k.ServerMacKey = expandLabel(h, k.HandshakeSecret, []byte(tagMacServer), nil)
	k.ClientMacKey = expandLabel(h, k.HandshakeSecret, []byte(tagMacClient), nil)
	k.HandshakeEncryptKey = expandLabel(h, k.HandshakeSecret, []byte(tagEncServer), nil)

	return k, sessionSecret
}

func decodeKeys(g group.Group, secret, peerEpk, peerPk []byte) (group.Scalar, group.Element, group.Element, error) {
	sk, err := g.NewScalar().Decode(secret)
	if err != nil {
		return nil, nil, nil, err
	}

	epk, err := g.NewElement().Decode(peerEpk)
	if err != nil {
		return nil, nil, nil, err
	}

	pk, err := g.NewElement().Decode(peerPk)
	if err != nil {
		return nil, nil, nil, err
	}

	return sk, epk, pk, nil
}

func k3dh(p1 group.Element, s1 group.Scalar, p2 group.Element, s2 group.Scalar, p3 group.Element, s3 group.Scalar) []byte {
	e1 := p1.Mult(s1)
	e2 := p2.Mult(s2)
	e3 := p3.Mult(s3)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes())
}
