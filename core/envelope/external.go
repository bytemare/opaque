package envelope

import (
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
	*internal.KDF
}

func (e *ExternalMode) BuildInnerEnvelope(prk []byte, creds *Credentials) (innerEnvelope, pk []byte) {
	sec := SecretCredentials{creds.Skx}
	pt := sec.Serialize()
	pad := e.Expand(prk, []byte(tagPad), len(pt))

	return internal.Xor(pt, pad), creds.Pkc
}

func (e *ExternalMode) RecoverSecret(prk, innerEnvelope []byte) *SecretCredentials {
	inner := deserializeExternalInnerEnvelope(innerEnvelope, e.Nsk)
	pad := e.Expand(prk, []byte(tagPad), len(inner.encrypted))
	pt := internal.Xor(inner.encrypted, pad)

	return DeserializeSecretCredentials(pt)
}
