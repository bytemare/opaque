package envelope

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/internal"
)

const (
	nonceLen     = 32
	tagPad       = "Pad"
	tagAuthKey   = "AuthKey"
	tagExportKey = "ExportKey"
)

var ErrEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")

type Keys struct {
	Group                        ciphersuite.Identifier
	Hash                         *hash.Hash
	Mhf                          *mhf.Parameters
	Pad, AuthKey, ExportKey, Prk []byte
}

func (k *Keys) buildRwdu(unblinded, nonce []byte) []byte {
	// hardened := c.Mhf.Harden(unblinded, nil)
	hardened := unblinded
	return k.Hash.HKDFExtract(hardened, nonce)
}

func (k *Keys) padKey(rwdu []byte, padLength int) {
	k.Pad = k.Hash.HKDFExpand(rwdu, []byte(tagPad), padLength)
}

func (k *Keys) buildKeys(rwdu []byte) {
	k.AuthKey = k.Hash.HKDFExpand(rwdu, []byte(tagAuthKey), k.Hash.OutputSize())
	k.ExportKey = k.Hash.HKDFExpand(rwdu, []byte(tagExportKey), k.Hash.OutputSize())
}

func (k *Keys) BuildEnvelope(unblinded, pks []byte, mode Mode, creds *Credentials) (*Envelope, []byte, error) {
	k.Prk = k.buildRwdu(unblinded, creds.Nonce)
	sec := SecretCredentials{Sku: creds.Sk}
	pt := sec.Serialize()

	k.padKey(k.Prk, len(pt))
	k.buildKeys(k.Prk)

	encryptedCreds := internal.Xor(pt, k.Pad)

	contents := &InnerEnvelope{
		Mode:           mode,
		Nonce:          creds.Nonce,
		EncryptedCreds: encryptedCreds,
	}

	clearCreds := encodeClearTextCredentials(creds.Idu, creds.Ids, pks, mode)

	tag := k.Hash.Hmac(append(contents.Serialize(), clearCreds...), k.AuthKey)
	envU := &Envelope{
		InnerEnv: contents,
		AuthTag:  tag,
	}

	return envU, k.ExportKey, nil
}

func (k *Keys) RecoverSecret(idu, ids, pks, unblinded []byte, envU *Envelope) (*SecretCredentials, []byte, error) {
	contents := envU.InnerEnv
	rwdu := k.buildRwdu(unblinded, contents.Nonce)
	k.buildKeys(rwdu)

	clearCreds := encodeClearTextCredentials(idu, ids, pks, contents.Mode)

	expectedTag := k.Hash.Hmac(append(contents.Serialize(), clearCreds...), k.AuthKey)

	if !hmac.Equal(expectedTag, envU.AuthTag) {
		return nil, nil, ErrEnvelopeInvalidTag
	}

	k.padKey(rwdu, len(contents.EncryptedCreds))
	pt := internal.Xor(contents.EncryptedCreds, k.Pad)
	sec := DeserializeSecretCredentials(pt)

	return sec, k.ExportKey, nil
}
