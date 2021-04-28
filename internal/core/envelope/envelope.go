package envelope

import (
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
)

var (
	errEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")
	errCorruptEnvelope = errors.New("envelope corrupted")
	errInvalidEnvLength = errors.New("envelope of invalid length")
	errInvalidSK = errors.New("invalid private key")
)

type Credentials struct {
	Idc, Ids                    []byte
	EnvelopeNonce, MaskingNonce []byte // todo: for testing only
}

type Mode byte

const (
	Internal Mode = iota + 1
	External
)

type Envelope struct {
	Nonce         []byte
	InnerEnvelope []byte
	AuthTag       []byte
}

func (e *Envelope) String() string {
	return fmt.Sprintf("Nonce: %v\nAuthTag: %v\nInnerEnvelope: %v\n", e.Nonce, e.AuthTag, e.InnerEnvelope)
}

func (e *Envelope) Serialize() []byte {
	return utils.Concatenate(0, e.Nonce, e.InnerEnvelope, e.AuthTag)
}

func Size(mode Mode, nn, nm int, id ciphersuite.Identifier) int {
	var innerSize int

	switch mode {
	case Internal:
		innerSize = 0
	case External:
		innerSize = internal.ScalarLength[id]
	default:
		panic("invalid envelope mode")
	}

	return nn + nm + innerSize
}

func DeserializeEnvelope(data []byte, mode Mode, nn, nm, nsk int) (*Envelope, int, error) {
	baseLen := nn + nm

	if len(data) < baseLen {
		return nil, 0, errCorruptEnvelope
	}

	if mode == External && len(data) != baseLen+nsk {
		return nil, 0, errInvalidEnvLength
	}

	nonce := data[:nn]
	innerLen := 0

	if mode == External {
		innerLen = nsk
	}

	inner := data[nn : nn+innerLen]
	tag := data[nn+innerLen:]

	return &Envelope{
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}, baseLen + len(inner), nil
}

type InnerEnvelope interface {
	BuildInnerEnvelope(randomizedPwd, nonce, skc []byte) (innerEnvelope, pk []byte)
	RecoverKeys(randomizedPwd, nonce, innerEnvelope []byte) (skc, pkc []byte)
}

type Mailer struct {
	*internal.Parameters
}

func (m *Mailer) inner(mode Mode) InnerEnvelope {
	var inner InnerEnvelope

	switch mode {
	case Internal:
		inner = &InternalMode{m.AKEGroup, m.KDF}
	case External:
		inner = &ExternalMode{internal.ScalarLength[m.AKEGroup], m.AKEGroup.Get(nil), m.KDF}
	default:
		panic("invalid mode")
	}

	return inner
}

func BuildPRK(p *internal.Parameters, unblinded []byte) []byte {
	// hardened := p.Harden(unblinded, nil)
	hardened := unblinded
	return p.KDF.Extract(nil, hardened)
}

func (m *Mailer) buildKeys(randomizedPwd, nonce []byte) (authKey, exportKey []byte) {
	authKey = m.KDF.Expand(randomizedPwd, internal.Concat(nonce, internal.TagAuthKey), m.KDF.Size())
	exportKey = m.KDF.Expand(randomizedPwd, internal.Concat(nonce, internal.TagExportKey), m.KDF.Size())

	return
}

func (m *Mailer) AuthTag(authKey, nonce, inner, ctc []byte) []byte {
	return m.MAC.MAC(authKey, utils.Concatenate(0, nonce, inner, ctc))
}

func (m *Mailer) CreateEnvelope(mode Mode, randomizedPwd, pks, skc []byte, creds *Credentials) (envelope *Envelope, publicKey, exportKey []byte) {
	// todo for testing only
	nonce := creds.EnvelopeNonce
	if nonce == nil {
		nonce = utils.RandomBytes(m.NonceLen)
	}

	authKey, exportKey := m.buildKeys(randomizedPwd, nonce)
	inner, pkc := m.inner(mode).BuildInnerEnvelope(randomizedPwd, nonce, skc)
	ctc := CreateCleartextCredentials(pkc, pks, creds)
	tag := m.AuthTag(authKey, nonce, inner, ctc.Serialize())

	envelope = &Envelope{
		Nonce:         nonce,
		InnerEnvelope: inner,
		AuthTag:       tag,
	}

	return envelope, pkc, exportKey
}

func (m *Mailer) RecoverEnvelope(mode Mode, randomizedPwd, pks []byte, creds *Credentials, envelope *Envelope) (skc, pkc, exportKey []byte, err error) {
	authKey, exportKey := m.buildKeys(randomizedPwd, envelope.Nonce)
	skc, pkc = m.inner(mode).RecoverKeys(randomizedPwd, envelope.Nonce, envelope.InnerEnvelope)
	ctc := CreateCleartextCredentials(pkc, pks, creds)

	expectedTag := m.AuthTag(authKey, envelope.Nonce, envelope.InnerEnvelope, ctc.Serialize())
	if !hmac.Equal(expectedTag, envelope.AuthTag) {
		return nil, nil, nil, errEnvelopeInvalidTag
	}

	return skc, pkc, exportKey, nil
}
