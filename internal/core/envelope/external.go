package envelope

import (
	"github.com/bytemare/cryptotools/group"

	"github.com/bytemare/opaque/internal"
)

type externalInnerEnvelope struct {
	encrypted []byte
}

func (e externalInnerEnvelope) Serialize() []byte {
	return e.encrypted
}

func deserializeExternalInnerEnvelope(inner []byte, nsk int) *externalInnerEnvelope {
	if len(inner) != nsk {
		panic("invalid inner envelope")
	}

	return &externalInnerEnvelope{inner}
}

type ExternalMode struct {
	Nsk int
	group.Group
	*internal.KDF
}

func (e *ExternalMode) RecoverPublicKey(privateKey group.Scalar) group.Element {
	return e.Base().Mult(privateKey)
}

func (e *ExternalMode) BuildInnerEnvelope(randomizedPwd, nonce, skc []byte) (innerEnvelope, pk []byte) {
	scalar, err := e.NewScalar().Decode(skc)
	if err != nil {
		panic(errInvalidSK)
	}

	pkc := e.Base().Mult(scalar).Bytes()
	pad := e.Expand(randomizedPwd, internal.Concat(nonce, internal.TagPad), len(skc))

	return externalInnerEnvelope{internal.Xor(skc, pad)}.Serialize(), pkc
}

func (e *ExternalMode) RecoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (skc, pkc []byte) {
	inner := deserializeExternalInnerEnvelope(innerEnvelope, e.Nsk)
	pad := e.Expand(randomizedPwd, internal.Concat(nonce, internal.TagPad), len(inner.encrypted))
	skc = internal.Xor(inner.encrypted, pad)

	sk, err := e.NewScalar().Decode(skc)
	if err != nil {
		panic(errInvalidSK)
	}

	return skc, e.RecoverPublicKey(sk).Bytes()
}
