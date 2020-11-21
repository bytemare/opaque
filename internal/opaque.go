// Package internal groups the inner mechanism and unexported API for the OPAQUE protocol
package internal

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/envelope/authenc"
	"github.com/bytemare/pake"
)

// Opaque is the OPAQUE core common to both the initiator and responder instances
type Opaque struct {
	// Pake engine
	*pake.Core

	// RKR Authenticated Encryption
	authenc.RKRAuthenticatedEncryption

	// Authenticated Key Exchange Protocol
	Kex ake.KeyExchange
}

// RegistrationPayload is the message a client sends to the server to register it's envelope and public key
type RegistrationPayload struct {
	PublicKey []byte
	Envelope  []byte
}

func (r *RegistrationPayload) Encode(e encoding.Encoding) ([]byte, error) {
	switch e {
	case encoding.Gob:
		return r.Gob()
	case encoding.JSON:
		return r.Json()
	// case encoding.Protobuf:
	//	return r.Protobuf()
	default:
		panic("Unregistered encoding")
	}
}

func (r *RegistrationPayload) Json() ([]byte, error) {
	return encoding.JSON.Encode(r)
}

func (r *RegistrationPayload) Gob() ([]byte, error) {
	return encoding.Gob.Encode(r)
}

func (r *RegistrationPayload) Protobuf() ([]byte, error) {
	panic("Protocol buffer are not yet supported")
}
