package envelope

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/opaque/internal"
)

type InternalMode struct {
	ciphersuite.Identifier
	*internal.KDF
}

func (i *InternalMode) DeriveSecretKey(seed []byte) group.Scalar {
	return i.Get(nil).HashToScalar(seed, []byte(internal.H2sDST))
}

func (i *InternalMode) DeriveAkeKeyPair(seed []byte) (group.Scalar, group.Element) {
	sk := i.DeriveSecretKey(seed)
	return sk, i.Get(nil).Base().Mult(sk)
}

func (i *InternalMode) BuildInnerEnvelope(randomizedPwd, nonce, _ []byte) (inner, pkc []byte) {
	seed := i.Expand(randomizedPwd, internal.Concat(nonce, internal.SkDST), internal.ScalarLength[i.Identifier])
	_, pk := i.DeriveAkeKeyPair(seed)

	return nil, internal.SerializePoint(pk, i.Identifier)
}

func (i *InternalMode) RecoverKeys(randomizedPwd, nonce, _ []byte) (skc, pkc []byte) {
	seed := i.Expand(randomizedPwd, internal.Concat(nonce, internal.SkDST), internal.ScalarLength[i.Identifier])
	sk, pk := i.DeriveAkeKeyPair(seed)

	return sk.Bytes(), pk.Bytes()
}
