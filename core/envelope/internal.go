package envelope

import (
	"github.com/bytemare/cryptotools/group"
)

const h2sDST = "Opaque-KeyGenerationSeed"

type InternalMode struct {
	group.Group
}

func (i *InternalMode) DeriveSecretKey(seed []byte) group.Scalar {
	return i.HashToScalar(seed, []byte(h2sDST))
}

func (i *InternalMode) DeriveKeyPair(seed []byte) (group.Scalar, group.Element) {
	sk := i.DeriveSecretKey(seed)
	return sk, i.Base().Mult(sk)
}

func (i *InternalMode) BuildInnerEnvelope(prk []byte, _ *Credentials) (inner, pkc []byte) {
	_, pk := i.DeriveKeyPair(prk)

	return nil, pk.Bytes()
}

func (i *InternalMode) RecoverSecret(prk, _ []byte) *SecretCredentials {
	return &SecretCredentials{Skc: i.DeriveSecretKey(prk).Bytes()}
}
