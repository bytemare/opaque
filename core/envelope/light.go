package envelope

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
)

const OptimalMode Mode = 2

type EnvelopeOpt struct {
	Nonce   []byte
	AuthTag []byte
}

type Optimal struct {
	Group ciphersuite.Identifier
	Hash  hash.Identifier
	*mhf.Parameters
}

func (o *Optimal) BuildEnvelopeOptimal(unblinded, pks, nonce []byte) (sku, pku []byte, envU *EnvelopeOpt) {
	if nonce == nil {
		nonce = utils.RandomBytes(nonceLen)
	}

	sk, pk, authTag := o.buildKeys(unblinded, pks, nonce)

	return sk.Bytes(), pk.Bytes(), &EnvelopeOpt{
		Nonce:   nonce,
		AuthTag: authTag,
	}
}

func (o *Optimal) RecoverSecret(unblinded, pks []byte, envU *EnvelopeOpt) (sk group.Scalar, pk group.Element, err error) {
	sk, pk, authTag := o.buildKeys(unblinded, pks, envU.Nonce)

	if !hmac.Equal(authTag, envU.AuthTag) {
		return nil, nil, errors.New("invalid mac")
	}

	return sk, pk, nil
}

func (o *Optimal) buildKeys(unblinded, pks, nonce []byte) (sk group.Scalar, pk group.Element, authTag []byte) {
	hardened := o.Parameters.Hash(unblinded, nil)
	h := o.Hash.Get()
	prk := h.HKDFExtract(hardened, nonce)

	dst := "Opaque-KeyGenerationSeed"
	g := o.Group.Get([]byte(dst))
	sk = g.HashToScalar(prk)
	pk = g.Base().Mult(sk)
	authKey := h.HKDFExpand(prk, []byte("AuthKey"), 0)
	authTag = h.Hmac(utils.Concatenate(0, nonce, pk.Bytes(), pks), authKey)

	return sk, pk, authTag
}
