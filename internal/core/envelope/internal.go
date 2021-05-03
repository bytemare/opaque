// Package envelope provides utility functions and structures allowing credential management.
package envelope

import (
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/opaque/internal"
)

type internalMode struct {
	ciphersuite.Identifier
	*internal.KDF
}

func (i *internalMode) deriveSecretKey(seed []byte) group.Scalar {
	return i.Get(nil).HashToScalar(seed, []byte(internal.H2sDST))
}

func (i *internalMode) deriveAkeKeyPair(seed []byte) (group.Scalar, group.Element) {
	sk := i.deriveSecretKey(seed)
	return sk, i.Get(nil).Base().Mult(sk)
}

func (i *internalMode) buildInnerEnvelope(randomizedPwd, nonce, _ []byte) (inner, pkc []byte) {
	seed := i.Expand(randomizedPwd, internal.Concat(nonce, internal.SkDST), internal.ScalarLength[i.Identifier])
	_, pk := i.deriveAkeKeyPair(seed)

	return nil, internal.SerializePoint(pk, i.Identifier)
}

func (i *internalMode) recoverKeys(randomizedPwd, nonce, _ []byte) (skc, pkc []byte) {
	seed := i.Expand(randomizedPwd, internal.Concat(nonce, internal.SkDST), internal.ScalarLength[i.Identifier])
	sk, pk := i.deriveAkeKeyPair(seed)

	return sk.Bytes(), pk.Bytes()
}
