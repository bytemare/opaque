package envelope

import (
	"crypto/hmac"
)

func (k *Keys) BuildEnvelopeNew(unblinded, pks []byte, mode Mode, creds *Credentials) (*Envelope, []byte, error) {
	k.Prk = k.buildRwdu(unblinded, creds.Nonce)
	k.buildKeys(k.Prk)

	innerEnv := mode.Get().BuildInnerEnvelope(k.Prk, creds, k)
	ctc := mode.Get().ClearTextCredentials(creds.Idu, creds.Ids, pks)
	tag := k.Hash.Hmac(append(innerEnv.Serialize(), ctc.Serialize()...), k.AuthKey)

	envU := &Envelope{
		InnerEnv: innerEnv,
		AuthTag:  tag,
	}

	return envU, k.ExportKey, nil
}

func (k *Keys) RecoverSecretNew(idu, ids, pks, unblinded []byte, envU *Envelope) (*SecretCredentials, []byte, error) {
	contents := envU.InnerEnv
	prk := k.buildRwdu(unblinded, contents.Nonce)
	k.buildKeys(prk)

	ctc := contents.Mode.Get().ClearTextCredentials(idu, ids, pks)
	expectedTag := k.Hash.Hmac(append(contents.Serialize(), ctc.Serialize()...), k.AuthKey)

	if !hmac.Equal(expectedTag, envU.AuthTag) {
		return nil, nil, ErrEnvelopeInvalidTag
	}

	sc := contents.Mode.Get().Recover(prk, k, envU.InnerEnv)

	return sc, k.ExportKey, nil
}
