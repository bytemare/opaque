package envelope

import "github.com/bytemare/opaque/internal"

type baseCleartextCredentials struct {
	Mode
	Pks []byte
}

func newBaseClearTextCredentials(pks []byte) *baseCleartextCredentials {
	return &baseCleartextCredentials{
		Mode: Base,
		Pks:  pks,
	}
}

func (b *baseCleartextCredentials) Serialize() []byte {
	return b.Pks
}

type BaseMode struct{}

func (b BaseMode) BuildInnerEnvelope(prk []byte, creds *Credentials, k *Keys) *InnerEnvelope {
	sec := SecretCredentials{Sku: creds.Sk}
	pt := sec.Serialize()
	k.padKey(prk, len(pt))

	encryptedCreds := internal.Xor(pt, k.Pad)

	return &InnerEnvelope{
		Mode:           Base,
		Nonce:          creds.Nonce,
		EncryptedCreds: encryptedCreds,
	}
}

func (b BaseMode) ClearTextCredentials(_, _, pks []byte) CleartextCredentials {
	return newBaseClearTextCredentials(pks)
}

func (b BaseMode) Recover(prk []byte, k *Keys, inner *InnerEnvelope) *SecretCredentials {
	k.padKey(prk, len(inner.EncryptedCreds))
	pt := internal.Xor(inner.EncryptedCreds, k.Pad)

	return DeserializeSecretCredentials(pt)
}
