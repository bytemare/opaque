package envelope

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

var ErrEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")

type Credentials struct {
	Idc, Ids                    []byte
	EnvelopeNonce, MaskingNonce []byte // todo: for testing only
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

func (e *Envelope) String() string {
	return fmt.Sprintf("mode: %v\nNonce: %v\nAuthTag: %v\nInnerEnvelope: %v\n", e.Mode, e.Nonce, e.AuthTag, e.InnerEnvelope)
}

func (e *Envelope) Serialize() []byte {
	return utils.Concatenate(0,
		[]byte{byte(e.Mode)}, e.Nonce, e.AuthTag, e.InnerEnvelope)
}

func Size(mode Mode, Nn, Nm int, id ciphersuite.Identifier) int {
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
	BuildInnerEnvelope(randomizedPwd, nonce, skc []byte) (innerEnvelope, pk []byte)
	RecoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (skc, pkc []byte)
}

type Thing struct {
	Mode
	*internal.Parameters
	// TODO testing
	AuthKey, PRK []byte
}

func NewThing(parameters *internal.Parameters, mode Mode) *Thing {
	// todo do checks on whether the necessary arguments are given
	return &Thing{
		Mode: mode,
		Parameters:parameters,
	}
}

func (t *Thing) inner(mode Mode) InnerEnvelope {
	var inner InnerEnvelope
	switch mode {
	case Internal:
		inner = &InternalMode{t.AKEGroup, t.KDF}
	case External:
		inner = &ExternalMode{internal.ScalarLength(t.AKEGroup), t.AKEGroup.Get(nil), t.KDF}
	default:
		panic("invalid mode")
	}

	return inner
}

func (t *Thing) BuildPRK(unblinded, nonce []byte) []byte {
	// hardened := t.Harden(unblinded, nil)
	hardened := unblinded
	return t.KDF.Extract(nonce, hardened)
}

func (t *Thing) buildKeys(randomizedPwd, nonce []byte) (authKey, exportKey, maskingKey []byte) {
	authKey = t.KDF.Expand(randomizedPwd, internal.Concat(nonce, tagAuthKey), t.KDF.Size())
	exportKey = t.KDF.Expand(randomizedPwd, internal.Concat(nonce, tagExportKey), t.KDF.Size())
	maskingKey = t.KDF.Expand(randomizedPwd, []byte(tagMaskingKey), t.KDF.Size())

	return
}

func (t *Thing) AuthTag(authKey, nonce, inner, ctc []byte) []byte {
	return t.MAC.MAC(authKey, utils.Concatenate(0, []byte{byte(t.Mode)}, nonce, inner, ctc))
}

func (t *Thing) CreateEnvelope(randomizedPwd, pks, skc []byte, creds *Credentials) (envelope *Envelope, publicKey, maskingKey, exportKey []byte) {
	// todo for testing only
	var nonce = creds.EnvelopeNonce
	if nonce == nil {
		nonce = utils.RandomBytes(t.NonceLen)
	}

	authKey, exportKey, maskingKey := t.buildKeys(randomizedPwd, nonce)
	inner, pkc := t.inner(t.Mode).BuildInnerEnvelope(randomizedPwd, nonce, skc)
	ctc := CreateCleartextCredentials(pkc, pks, creds)
	tag := t.AuthTag(authKey, nonce, inner, ctc.Serialize())

	// todo testing
	t.AuthKey = authKey
	t.PRK = randomizedPwd

	envelope = &Envelope{
		Mode:          t.Mode,
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}

	return envelope, pkc, maskingKey, exportKey
}

func (t *Thing) RecoverEnvelope(randomizedPwd, pks []byte, creds *Credentials, envelope *Envelope) (skc, pkc, exportKey []byte, err error) {
	authKey := t.KDF.Expand(randomizedPwd, internal.Concat(envelope.Nonce, tagAuthKey), t.KDF.Size())
	exportKey = t.KDF.Expand(randomizedPwd, internal.Concat(envelope.Nonce, tagExportKey), t.KDF.Size())
	skc, pkc = t.inner(t.Mode).RecoverKeys(randomizedPwd, envelope.Nonce, envelope.InnerEnvelope)
	ctc := CreateCleartextCredentials(pkc, pks, creds)

	expectedTag := t.AuthTag(authKey, envelope.Nonce, envelope.InnerEnvelope, ctc.Serialize())
	if !hmac.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, ErrEnvelopeInvalidTag
	}

	return skc, pkc, exportKey, nil
}
