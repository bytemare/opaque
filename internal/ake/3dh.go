// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encode"

	"github.com/bytemare/opaque/message"
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
	return utils.Concatenate(0,
		encoding.I2OSP(length, 2),
		encode.EncodeVectorLen(append([]byte(internal.LabelPrefix), label...), 1),
		encode.EncodeVectorLen(context, 1))
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
	cp := encode.EncodeVectorLen(idu, 2)
	sp := encode.EncodeVectorLen(ids, 2)
	_, _ = h.Write(utils.Concatenate(0, []byte(internal.Tag3DH), cp, ke1.Serialize(), sp, response, nonceS, epks))
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (keys *Keys, sessionSecret []byte) {
	prk := h.Extract(nil, ikm)
	keys = &Keys{}
	keys.HandshakeSecret = deriveSecret(h, prk, []byte(internal.TagHandshake), context)
	sessionSecret = deriveSecret(h, prk, []byte(internal.TagSession), context)
	keys.ServerMacKey = expandLabel(h, keys.HandshakeSecret, []byte(internal.TagMacServer), nil)
	keys.ClientMacKey = expandLabel(h, keys.HandshakeSecret, []byte(internal.TagMacClient), nil)
	keys.HandshakeEncryptKey = expandLabel(h, keys.HandshakeSecret, []byte(internal.TagEncServer), nil)

	return keys, sessionSecret
}

func decodeKeys(g group.Group, secret, peerEpk, peerPk []byte) (sk group.Scalar, epk, pk group.Element, err error) {
	sk, err = g.NewScalar().Decode(secret)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding secret key: %w", err)
	}

	epk, err = g.NewElement().Decode(peerEpk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding peer ephemeral public key: %w", err)
	}

	pk, err = g.NewElement().Decode(peerPk)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding peer public key: %w", err)
	}

	return sk, epk, pk, nil
}

func k3dh(p1 group.Element, s1 group.Scalar, p2 group.Element, s2 group.Scalar, p3 group.Element, s3 group.Scalar) []byte {
	e1 := p1.Mult(s1)
	e2 := p2.Mult(s2)
	e3 := p3.Mult(s3)

	return utils.Concatenate(0, e1.Bytes(), e2.Bytes(), e3.Bytes())
}
