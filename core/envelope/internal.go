package envelope

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/internal"
)

const h2sDST = "Opaque-KeyGenerationSeed"

type InternalMode struct {
	ciphersuite.Identifier
}

func (i *InternalMode) DeriveSecretKey(seed []byte) group.Scalar {
	return i.Get(nil).HashToScalar(seed, []byte(h2sDST))
}

func (i *InternalMode) DeriveKeyPair(seed []byte) (group.Scalar, group.Element) {
	sk := i.DeriveSecretKey(seed)
	return sk, i.Get(nil).Base().Mult(sk)
}

func (i *InternalMode) BuildInnerEnvelope(prk []byte, _ *Credentials) (inner, pkc []byte) {
	_, pk := i.DeriveKeyPair(prk)

	return nil, internal.SerializePoint(pk, i.Identifier)
}

func (i *InternalMode) RecoverSecret(prk, _ []byte) *SecretCredentials {
	return &SecretCredentials{Skc: i.DeriveSecretKey(prk).Bytes()}
}
