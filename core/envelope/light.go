package envelope

import (
	"github.com/bytemare/cryptotools/group"
)

const OptimalMode Mode = 2

const h2sDST = "Opaque-KeyGenerationSeed"

func deriveSecretKey(g group.Group, prk []byte) group.Scalar {
	return g.HashToScalar(prk, []byte(h2sDST))
}

type SeedMode struct{}

func (s SeedMode) BuildInnerEnvelope(prk []byte, creds *Credentials, k *Keys) *InnerEnvelope {
	sk := deriveSecretKey(k.Group, prk)
	pk := k.Group.Base().Mult(sk)
	creds.Sk = sk.Bytes()
	creds.Pk = pk.Bytes()

	return &InnerEnvelope{
		Mode:  Base,
		Nonce: creds.Nonce,
	}
}

func (s SeedMode) ClearTextCredentials(idu, ids, pks []byte) CleartextCredentials {
	return &customCleartextCredentials{
		Mode: OptimalMode,
		Pks:  pks,
		Idu:  idu,
		Ids:  ids,
	}
}

func (s SeedMode) Recover(prk []byte, k *Keys, _ *InnerEnvelope) *SecretCredentials {
	return &SecretCredentials{Sku: deriveSecretKey(k.Group, prk).Bytes()}
}
