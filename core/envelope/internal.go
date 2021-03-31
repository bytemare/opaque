package envelope

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/internal"
)

const (
	h2sDST = "Opaque-KeyGenerationSeed"
	skDST  = "PrivateKey"
)

type InternalMode struct {
	ciphersuite.Identifier
	*internal.KDF
}

func (i *InternalMode) DeriveSecretKey(seed []byte) group.Scalar {
	return i.Get(nil).HashToScalar(seed, []byte(h2sDST))
}

func (i *InternalMode) DeriveKeyPair(seed []byte) (group.Scalar, group.Element) {
	sk := i.DeriveSecretKey(seed)
	return sk, i.Get(nil).Base().Mult(sk)
}

func (i *InternalMode) BuildInnerEnvelope(prk, nonce, _ []byte) (inner, pkc []byte) {
	seed := i.Expand(prk, internal.ExtendNonce(nonce, skDST), 32)
	_, pk := i.DeriveKeyPair(seed)

	return nil, internal.SerializePoint(pk, i.Identifier)
}

func (i *InternalMode) RecoverKeys(prk, nonce, _ []byte) (*SecretCredentials, []byte) {
	seed := i.Expand(prk, internal.ExtendNonce(nonce, skDST), 32)
	skc, pkc := i.DeriveKeyPair(seed)
	return &SecretCredentials{Skc: skc.Bytes()}, pkc.Bytes()
}
