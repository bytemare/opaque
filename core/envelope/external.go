package envelope

import (
	"errors"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/opaque/internal"
)

const tagPad = "Pad"

type externalInnerEnvelope struct {
	encrypted []byte
}

func (e *externalInnerEnvelope) Serialize() []byte {
	return e.encrypted
}

func deserializeExternalInnerEnvelope(inner []byte, Nsk int) *externalInnerEnvelope {
	if len(inner) != Nsk {
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

func (e *ExternalMode) BuildInnerEnvelope(prk, nonce, skc []byte) (innerEnvelope, pk []byte) {
	scalar, err := e.NewScalar().Decode(skc)
	if err != nil {
		panic(errors.New("invalid private key"))
	}

	pkc := e.Base().Mult(scalar).Bytes()
	sec := SecretCredentials{skc}
	pt := sec.Serialize()
	pad := e.Expand(prk, internal.ExtendNonce(nonce, tagPad), len(pt))

	return internal.Xor(pt, pad), pkc
}

func (e *ExternalMode) RecoverKeys(prk, nonce, innerEnvelope []byte) (*SecretCredentials, []byte) {
	inner := deserializeExternalInnerEnvelope(innerEnvelope, e.Nsk)
	pad := e.Expand(prk, internal.ExtendNonce(nonce, tagPad), len(inner.encrypted))
	pt := internal.Xor(inner.encrypted, pad)
	sc := DeserializeSecretCredentials(pt)

	skc, err := e.NewScalar().Decode(sc.Skc)
	if err != nil {
		panic(errors.New("invalid private key"))
	}

	return sc, e.RecoverPublicKey(skc).Bytes()
}
