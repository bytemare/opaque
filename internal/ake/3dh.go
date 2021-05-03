// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"fmt"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
)

// KeyGen returns private and public keys in the grouo.
func KeyGen(id ciphersuite.Identifier) (sk, pk []byte) {
	g := id.Get(nil)
	scalar := g.NewScalar().Random()
	publicKey := g.Base().Mult(scalar)

	return internal.SerializeScalar(scalar, id), internal.SerializePoint(publicKey, id)
}

type keys struct {
	serverMacKey, clientMacKey []byte
	handshakeSecret            []byte
	handshakeEncryptKey        []byte
}

type ake struct {
	*internal.Parameters
	group.Group
	SessionSecret []byte
}

// setValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func setValues(p *internal.Parameters, scalar group.Scalar, nonce []byte, nonceLen int) (s group.Scalar, n []byte) {
	if scalar != nil {
		s = scalar
	} else {
		s = p.AKEGroup.Get(nil).NewScalar().Random()
	}

	if len(nonce) == 0 {
		nonce = utils.RandomBytes(nonceLen)
	}

	return s, nonce
}

func buildLabel(length int, label, context []byte) []byte {
	return utils.Concatenate(0,
		encoding.I2OSP(length, 2),
		encoding.EncodeVectorLen(append([]byte(internal.LabelPrefix), label...), 1),
		encoding.EncodeVectorLen(context, 1))
}

func expand(h *internal.KDF, secret, hkdfLabel []byte) []byte {
	return h.Expand(secret, hkdfLabel, h.Size())
}

func expandLabel(h *internal.KDF, secret, label, context []byte) []byte {
	hkdfLabel := buildLabel(h.Size(), label, context)
	return expand(h, secret, hkdfLabel)
}

func deriveSecret(h *internal.KDF, secret, label, context []byte) []byte {
	return expandLabel(h, secret, label, context)
}

func newInfo(h *internal.Hash, ke1 *message.KE1, idu, ids, response, nonceS, epks []byte) {
	cp := encoding.EncodeVectorLen(idu, 2)
	sp := encoding.EncodeVectorLen(ids, 2)
	h.Write(utils.Concatenate(0, []byte(internal.Tag3DH), cp, ke1.Serialize(), sp, response, nonceS, epks))
}

func deriveKeys(h *internal.KDF, ikm, context []byte) (k *keys, sessionSecret []byte) {
	prk := h.Extract(nil, ikm)
	k = &keys{}
	k.handshakeSecret = deriveSecret(h, prk, []byte(internal.TagHandshake), context)
	sessionSecret = deriveSecret(h, prk, []byte(internal.TagSession), context)
	k.serverMacKey = expandLabel(h, k.handshakeSecret, []byte(internal.TagMacServer), nil)
	k.clientMacKey = expandLabel(h, k.handshakeSecret, []byte(internal.TagMacClient), nil)
	k.handshakeEncryptKey = expandLabel(h, k.handshakeSecret, []byte(internal.TagEncServer), nil)

	return k, sessionSecret
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
