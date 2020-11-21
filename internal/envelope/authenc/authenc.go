// Package authenc provides random-key robust authenticated encryption schemes,
// as defined in section 3.1.1 of https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03
package authenc

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/internal/envelope/authenc/ctr"
)

// Identifier defines registered RKRAuthenticatedEncryption implementations
type Identifier string

const (
	// AesCtrHmacSha256 identifies the AES-CTR-Encrypt_then_HMAC-SHA2-256 implementation
	AesCtrHmacSha256 Identifier = "AES-CTR-Encrypt_then_HMAC-SHA2-256"

	// Default is set to AesCtrHmacSha256
	Default = AesCtrHmacSha256
)

// RKRAuthenticatedEncryption offers an interface to random-key robust (RKR) authenticated encryption (AE) schemes
type RKRAuthenticatedEncryption interface {

	// Encrypt uses key to encrypt the input plaintext
	Encrypt(key, plaintext []byte) []byte

	// Decrypt uses key to decrypt the encrypted input
	Decrypt(key, ciphertext []byte) ([]byte, error)
}

// New returns a RKRAuthenticatedEncryption implementation specified by identifier
func New(identifier Identifier) RKRAuthenticatedEncryption {
	if identifier == AesCtrHmacSha256 {
		return &ctr.AesCtrHmacSha256{Hash: hash.SHA256.Get()}
	}

	panic("unknown AuthenticatedEncryption identifier")
}
