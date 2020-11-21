// Package signature provides an additional abstraction and modularity to digital signature schemes of built-in implementations
package signature

import (
	"github.com/bytemare/opaque/internal/signature/ed25519"
)

// Identifier indicates the signature scheme to be used
type Identifier string

const (
	// Ed25519 indicates usage of the Ed25519 signature scheme
	Ed25519 Identifier = "Ed25519"

	//
	// Ed448 Identifier = "Ed448"
)

// Signature abstracts digital signature operations, wrapping built-in implementations
type Signature interface {
	// LoadKey loads the given key. Will not fail if the key is invalid, but it might later.
	//
	// The implementation can also handle this as a seed to re-calculate the private key, thus reducing storage size.
	LoadKey(privateKey []byte)

	// GenerateKey generates a fresh signing key and keeps it internally
	GenerateKey() error

	// GetPrivateKey returns the private key
	GetPrivateKey() []byte

	// GetPublicKey returns the public key
	GetPublicKey() []byte

	// Sign uses the internal private key to sign the message. The message argument doesn't need to be hashed beforehand.
	Sign(message ...[]byte) []byte

	// Verify checks whether signature of the message is valid given the public key
	Verify(publicKey, message, signature []byte) bool

	// Wipe ensures the secret key is correctly wiped from memory
	// Wipe()
}

// New returns a Signature implementation to the specified scheme
func New(identifier Identifier) Signature {
	if identifier == Ed25519 {
		return ed25519.New()
	}

	panic("unknown Signature identifier")
}
