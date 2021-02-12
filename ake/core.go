package ake

import (
	"crypto/hmac"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

const (
	labelPrefix  = "OPAQUE "
	tagHandshake = "handshake secret"
	tagSession   = "session secret"
	tagMacServer = "server mac"
	tagMacClient = "client mac"
	tagEncServer = "handshake enc"
)

type Ake struct {
	group.Group
	*hash.Hash
	NonceU        []byte
	NonceS        []byte
	Esk           group.Scalar
	Epk           group.Element
	SessionSecret []byte

	*Keys
}

func (a *Ake) Initialize(scalar group.Scalar, nonce []byte, nonceLen int) []byte {
	if a.Esk == nil {
		if scalar != nil {
			a.Esk = scalar
		} else {
			a.Esk = a.NewScalar().Random()
		}
	}

	a.Epk = a.Base().Mult(a.Esk)

	if nonce != nil {
		return nonce
	} else {
		return utils.RandomBytes(nonceLen)
	}
}

func (a *Ake) checkHmac(transcript2, key, mac []byte) bool {
	expectedHmac2 := a.Hmac(transcript2, key)
	return hmac.Equal(expectedHmac2, mac)
}

func buildLabel(length int, label, context []byte) []byte {
	// todo : the encodings here assume every length fits into a 1-byte encoding
	return utils.Concatenate(0, encoding.I2OSP(length, 2), internal.EncodeVectorLen(append([]byte(labelPrefix), label...), 1), internal.EncodeVectorLen(context, 1))
}

func hkdfExpand(h *hash.Hash, secret, hkdfLabel []byte) []byte {
	return h.HKDFExpand(secret, hkdfLabel, h.OutputSize())
}

func hkdfExpandLabel(h *hash.Hash, secret, label, context []byte) []byte {
	hkdfLabel := buildLabel(h.OutputSize(), label, context)
	return hkdfExpand(h, secret, hkdfLabel)
}

func DeriveSecret(h *hash.Hash, secret, label, transcript []byte) []byte {
	return hkdfExpandLabel(h, secret, label, h.Hash(0, transcript))
}

func info(protoTag, nonceU, nonceS, idU, idS []byte) []byte {
	return utils.Concatenate(0, protoTag,
		internal.EncodeVectorLen(nonceU, 2),
		internal.EncodeVectorLen(nonceS, 2),
		internal.EncodeVectorLen(idU, 2),
		internal.EncodeVectorLen(idS, 2))
}

type Keys struct {
	ServerMac, ClientMac []byte
	HandshakeSecret      []byte
	HandshakeEncryptKey  []byte
	SessionSecret        []byte
}

func DeriveKeys(h *hash.Hash, tag, idu, nonceU, ids, nonceS, ikm []byte) *Keys {
	info := info(tag, nonceU, nonceS, idu, ids)
	prk := h.HKDFExtract(ikm, nil)
	k := &Keys{}
	k.HandshakeSecret = DeriveSecret(h, prk, []byte(tagHandshake), info)
	k.SessionSecret = DeriveSecret(h, prk, []byte(tagSession), info)
	k.ServerMac = hkdfExpandLabel(h, k.HandshakeSecret, []byte(tagMacServer), nil)
	k.ClientMac = hkdfExpandLabel(h, k.HandshakeSecret, []byte(tagMacClient), nil)
	k.HandshakeEncryptKey = hkdfExpandLabel(h, k.HandshakeSecret, []byte(tagEncServer), nil)

	return k
}
