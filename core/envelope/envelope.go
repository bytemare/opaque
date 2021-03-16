package envelope

import (
	"crypto/hmac"
	"errors"
	"github.com/bytemare/cryptotools/group"
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

func DeserializeEnvelope(data []byte, Nm int) (*Envelope, error) {
	minLen := 1 + nonceLen + Nm
	if len(data) < 1 {
		return nil, errors.New("envelope corrupted")
	}

	mode := Mode(data[0])

	if mode == Internal && len(data) != minLen {
		return nil, errors.New("invalid envelope encoding")
	}

	if mode == External && len(data) <= minLen {
		return nil, errors.New("envelope encoding")
	}

	nonce := data[1 : 1+nonceLen]
	tag := data[1+nonceLen : 1+nonceLen+Nm]

	var inner []byte
	if mode == External {
		inner = data[1+nonceLen+Nm:]
	}

	return &Envelope{
		Mode:          mode,
		Nonce:         nonce,
		AuthTag:       tag,
		InnerEnvelope: inner,
	}, nil
}

type InnerEnvelope interface {
	BuildInnerEnvelope(prk []byte, creds *Credentials) (innerEnvelope, pk []byte)
	RecoverSecret(prk, innerEnvelope []byte) *SecretCredentials
}

type Thing struct {
	group.Group
	*internal.KDF
	*internal.Mac
	*internal.MHF
	Mode
}

func NewThing(g group.Group, kdf *internal.KDF, mac *internal.Mac, mhf *internal.MHF, mode Mode) *Thing {
	// todo do checks on whether the necessary arguments are given
	return &Thing{
		Group: g,
		KDF:   kdf,
		Mac:   mac,
		MHF:   mhf,
		Mode:  mode,
	}
}

func (t *Thing) inner() InnerEnvelope {
	var inner InnerEnvelope
	switch t.Mode {
	case Internal:
		inner = &InternalMode{t.Group}
	case External:
		inner = &ExternalMode{t.Group.ElementLength(), t.KDF} // todo element length won't work here
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

	return sc, exportKey, nil
}

type Credentials struct {
	Skx, Pkc, Pks, Idc, Ids, Nonce []byte
}
