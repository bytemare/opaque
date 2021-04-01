package envelope

import (
	"crypto/hmac"
	"errors"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

var ErrEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")

type Credentials struct {
	Idc, Ids []byte
}

type Mode byte

const (
	Internal Mode = iota + 1
	External

	tagAuthKey    = "AuthKey"
	tagExportKey  = "ExportKey"
	tagMaskingKey = "MaskingKey"
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

func EnvelopeSize(mode Mode, Nn, Nm int, id ciphersuite.Identifier) int {
	var innerSize int
	switch mode {
	case Internal:
		innerSize = 0
	case External:
		innerSize = internal.ScalarLength(id)
	default:
		panic("invalid envelope mode")
	}

	return 1 + Nn + Nm + innerSize
}

func DeserializeEnvelope(data []byte, Nn, Nm, Nsk int) (*Envelope, int, error) {
	baseLen := 1 + Nn + Nm

	if len(data) < 1+Nn+Nm {
		return nil, 0, errors.New("envelope corrupted")
	}

	mode := Mode(data[0])

	if mode == External && len(data) < baseLen+Nsk {
		return nil, 0, errors.New("envelope too short")
	}

	nonce := data[1 : 1+Nn]
	tag := data[1+Nn : baseLen]

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
	BuildInnerEnvelope(prk, nonce, skc []byte) (innerEnvelope, pk []byte)
	RecoverKeys(prk, nonce, innerEnvelope []byte) (*SecretCredentials, []byte)
}

type Thing struct {
	ciphersuite.Identifier
	*internal.KDF
	*internal.Mac
	*internal.MHF
	Mode
	nonceLen int
}

func NewThing(id ciphersuite.Identifier, kdf *internal.KDF, mac *internal.Mac, mhf *internal.MHF, mode Mode, nonceLen int) *Thing {
	// todo do checks on whether the necessary arguments are given
	return &Thing{
		Identifier: id,
		KDF:        kdf,
		Mac:        mac,
		MHF:        mhf,
		Mode:       mode,
		nonceLen:   nonceLen,
	}
}

func (t *Thing) inner() InnerEnvelope {
	var inner InnerEnvelope
	switch t.Mode {
	case Internal:
		inner = &InternalMode{t.Identifier, t.KDF}
	case External:
		inner = &ExternalMode{internal.ScalarLength(t.Identifier), t.Identifier.Get(nil), t.KDF} // todo element length won't work here
	default:
		panic("invalid mode")
	}

	return inner
}

func (t *Thing) BuildPRK(unblinded, nonce []byte) []byte {
	// hardened := t.Harden(unblinded, nil)
	hardened := unblinded
	return t.Extract(nonce, hardened)
}

func (t *Thing) buildKeys(prk, nonce []byte) (authKey, exportKey, maskingKey []byte) {
	authKey = t.Expand(prk, internal.ExtendNonce(nonce, tagAuthKey), t.KDF.Size())
	exportKey = t.Expand(prk, internal.ExtendNonce(nonce, tagExportKey), t.KDF.Size())
	maskingKey = t.Expand(prk, []byte(tagMaskingKey), t.KDF.Size())

	return
}

func (t *Thing) AuthTag(authKey, nonce, inner, ctc []byte) []byte {
	return t.MAC(authKey, utils.Concatenate(0, []byte{byte(t.Mode)}, nonce, inner, ctc))
}

func (t *Thing) CreateEnvelope(prk, pks, skc []byte, creds *Credentials) (envelope *Envelope, publicKey, maskingKey, exportKey []byte) {
	nonce := utils.RandomBytes(t.nonceLen)
	authKey, exportKey, maskingKey := t.buildKeys(prk, nonce)
	inner, pkc := t.inner().BuildInnerEnvelope(prk, nonce, skc)
	ctc := CreateCleartextCredentials(pkc, pks, creds)
	tag := t.AuthTag(authKey, nonce, inner, ctc.Serialize())

	envelope = &Envelope{
		Mode:          t.Mode,
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}

	return envelope, pkc, maskingKey, exportKey
}

func (t *Thing) RecoverEnvelope(prk, pks []byte, creds *Credentials, envelope *Envelope) (sc *SecretCredentials, pkc, exportKey []byte, err error) {
	authKey := t.Expand(prk, internal.ExtendNonce(envelope.Nonce, tagAuthKey), t.KDF.Size())
	exportKey = t.Expand(prk, internal.ExtendNonce(envelope.Nonce, tagExportKey), t.KDF.Size())
	sc, pkc = t.inner().RecoverKeys(prk, envelope.Nonce, envelope.InnerEnvelope)
	ctc := CreateCleartextCredentials(pkc, pks, creds)

	expectedTag := t.AuthTag(authKey, envelope.Nonce, envelope.InnerEnvelope, ctc.Serialize())
	if !hmac.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, ErrEnvelopeInvalidTag
	}

	return sc, pkc, exportKey, nil
}
