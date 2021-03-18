package envelope

import (
	"crypto/hmac"
	"errors"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

var ErrEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")

type Mode byte

const (
	Internal Mode = iota + 1
	External

	nonceLen     = 32
	tagAuthKey   = "AuthKey"
	tagExportKey = "ExportKey"
)

type Envelope struct {
	Mode
	Nonce         []byte
	AuthTag       []byte
	InnerEnvelope []byte
}

func (e *Envelope) Serialize() []byte {
	return utils.Concatenate(0,
		[]byte{byte(e.Mode)}, e.Nonce, e.AuthTag, e.InnerEnvelope)
}

func EnvelopeSize(mode Mode, nm int, id ciphersuite.Identifier) int {
	var size int
	switch mode {
	case Internal:
		size = 0
	case External:
		size = internal.ScalarLength(id)
	default:
		panic("invalid envelope mode")
	}

	return 1 + nonceLen + nm + size
}

func DeserializeEnvelope(data []byte, Nm, Nsk int) (*Envelope, int, error) {
	if len(data) < 1 {
		return nil, 0, errors.New("envelope corrupted")
	}

	mode := Mode(data[0])
	baseLen := 1 + nonceLen + Nm

	if len(data) < baseLen+Nsk {
		if mode == External || len(data) < baseLen {
			return nil, 0, errors.New("envelope too short")
		}
	}

	nonce := data[1 : 1+nonceLen]
	tag := data[1+nonceLen : baseLen]

	var inner []byte
	if mode == External {
		inner = data[baseLen : baseLen+Nsk]
	}

	return &Envelope{
		Mode:          mode,
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}, baseLen + len(inner), nil
}

type InnerEnvelope interface {
	BuildInnerEnvelope(prk []byte, creds *Credentials) (innerEnvelope, pk []byte)
	RecoverSecret(prk, innerEnvelope []byte) *SecretCredentials
}

type Thing struct {
	ciphersuite.Identifier
	*internal.KDF
	*internal.Mac
	*internal.MHF
	Mode
}

func NewThing(id ciphersuite.Identifier, kdf *internal.KDF, mac *internal.Mac, mhf *internal.MHF, mode Mode) *Thing {
	// todo do checks on whether the necessary arguments are given
	return &Thing{
		Identifier: id,
		KDF:        kdf,
		Mac:        mac,
		MHF:        mhf,
		Mode:       mode,
	}
}

func (t *Thing) inner() InnerEnvelope {
	var inner InnerEnvelope
	switch t.Mode {
	case Internal:
		inner = &InternalMode{t.Identifier}
	case External:
		inner = &ExternalMode{internal.ScalarLength(t.Identifier), t.KDF} // todo element length won't work here
	default:
		panic("invalid mode")
	}

	return inner
}

func (t *Thing) buildPRK(unblinded, nonce []byte) []byte {
	//hardened := t.Harden(unblinded, nil)
	hardened := unblinded
	return t.Extract(nonce, hardened)
}

func (t *Thing) buildKeys(unblinded, nonce []byte) (prk, authKey, exportKey []byte) {
	prk = t.buildPRK(unblinded, nonce)
	authKey = t.Expand(prk, []byte(tagAuthKey), t.KDF.Size())
	exportKey = t.Expand(prk, []byte(tagExportKey), t.KDF.Size())

	return
}

func (t *Thing) AuthTag(authKey, nonce, inner, ctc []byte) []byte {
	return t.MAC(authKey, utils.Concatenate(0, []byte{byte(t.Mode)}, nonce, inner, ctc))
}

func (t *Thing) CreateEnvelope(unblinded, pks []byte, creds *Credentials) (envelope *Envelope, pkc, exportKey []byte) {
	nonce := utils.RandomBytes(nonceLen)
	prk, authKey, exportKey := t.buildKeys(unblinded, nonce)

	inner, pkc := t.inner().BuildInnerEnvelope(prk, creds)
	ctc := CreateCleartextCredentials(pkc, pks, creds)
	tag := t.AuthTag(authKey, nonce, inner, ctc.Serialize())

	envelope = &Envelope{
		Mode:          t.Mode,
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}

	return envelope, pkc, exportKey
}

func (t *Thing) RecoverSecret(unblinded, pks []byte, creds *Credentials, envelope *Envelope) (*SecretCredentials, []byte, error) {
	prk, authKey, exportKey := t.buildKeys(unblinded, envelope.Nonce)
	ctc := CreateCleartextCredentials(creds.Pkc, pks, creds)
	expectedTag := t.AuthTag(authKey, envelope.Nonce, envelope.InnerEnvelope, ctc.Serialize())

	if !hmac.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, ErrEnvelopeInvalidTag
	}

	sc := t.inner().RecoverSecret(prk, envelope.InnerEnvelope)

	if len(sc.Skc) != internal.ScalarLength(t.Identifier) {
		return nil, nil, errors.New("recovered private key is of invalid length")
	}

	return sc, exportKey, nil
}

type Credentials struct {
	Skx, Pkc, Pks, Idc, Ids, Nonce []byte
}
