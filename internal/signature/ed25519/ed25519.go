// Package ed25519 is a simple wrapper around the standard library crypto/ed22519 package
package ed25519

import (
	"crypto/ed25519"

	"github.com/bytemare/cryptotools/utils"
)

const pointLen = 32

// Ed25519 implements the Signature interfaces and wraps crypto/ed22519.
type Ed25519 struct {
	privateKey ed25519.PrivateKey // todo : this is sensitive and should be cleared from memory
}

// New returns an empty Ed25519 structure.
func New() *Ed25519 {
	return &Ed25519{privateKey: nil}
}

// LoadKey loads the given key. Will not fail if the key is invalid, but it might later.
func (ed *Ed25519) LoadKey(seed []byte) {
	ed.privateKey = ed25519.NewKeyFromSeed(seed)
}

// GenerateKey generates a fresh signing key and stores it in ed.
func (ed *Ed25519) GenerateKey() error {
	var err error
	_, ed.privateKey, err = ed25519.GenerateKey(nil)

	return err
}

// GetPrivateKey returns the private key's seed, reducing by half the needed storage.
func (ed *Ed25519) GetPrivateKey() []byte {
	return ed.privateKey.Seed()
}

// GetPublicKey returns the public key.
func (ed *Ed25519) GetPublicKey() []byte {
	if ed.privateKey == nil {
		panic("private key is not set")
	}

	publicKey := make([]byte, 0, ed25519.PublicKeySize)

	publicKey = append(publicKey, ed.privateKey[pointLen:]...)

	return publicKey
}

// Sign uses the private key in ed to sign the input. The input doesn't need to be hashed beforehand.
func (ed *Ed25519) Sign(message ...[]byte) []byte {
	// Sign is mainly used to sign the two Sigma-I public elements,
	// so the length is estimated at twice the size of a point
	m := utils.Concatenate(pointLen*2, message...)

	return ed25519.Sign(ed.privateKey, m)
}

// Verify checks whether signature of the message is valid given the public key.
func (ed *Ed25519) Verify(publicKey, message, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}
