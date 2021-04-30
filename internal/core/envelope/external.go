package envelope

import (
	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/opaque/internal"
)

type externalInnerEnvelope struct {
	encrypted []byte
}

func (e externalInnerEnvelope) serialize() []byte {
	return e.encrypted
}

func deserializeExternalInnerEnvelope(inner []byte, nsk int) *externalInnerEnvelope {
	if len(inner) != nsk {
		panic("invalid inner envelope")
	}

	return &externalInnerEnvelope{inner}
}

type externalMode struct {
	Nsk int
	group.Group
	*internal.KDF
}

func (e *externalMode) recoverPublicKey(privateKey group.Scalar) group.Element {
	return e.Base().Mult(privateKey)
}

func (e *externalMode) buildInnerEnvelope(randomizedPwd, nonce, skc []byte) (innerEnvelope, pk []byte) {
	scalar, err := e.NewScalar().Decode(skc)
	if err != nil {
		panic(errInvalidSK)
	}

	pkc := e.Base().Mult(scalar).Bytes()
	pad := e.Expand(randomizedPwd, internal.Concat(nonce, internal.TagPad), len(skc))

	return externalInnerEnvelope{internal.Xor(skc, pad)}.serialize(), pkc
}

func (e *externalMode) recoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (skc, pkc []byte) {
	inner := deserializeExternalInnerEnvelope(innerEnvelope, e.Nsk)
	pad := e.Expand(randomizedPwd, internal.Concat(nonce, internal.TagPad), len(inner.encrypted))
	skc = internal.Xor(inner.encrypted, pad)

	sk, err := e.NewScalar().Decode(skc)
	if err != nil {
		panic(errInvalidSK)
	}

	return skc, e.recoverPublicKey(sk).Bytes()
}
