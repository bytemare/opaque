// Package ctr provides encryption and decryption functions for AES-CTR with Encrypt-then-HMAC authenticated encryption
// ensuring Random-Key Robustness as defined in section 3.1.1 of https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-03
package ctr

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/utils"
)

const (
	hkdfInfo = "EnvelopeEncryptAesCtrHmacSha512"

	// Key Length
	ivLength   = 16
	encLength  = 32
	macLength  = 32
	hkdfLength = encLength + macLength
)

// AesCtrHmacSha256 implements the RKRAuthenticatedEncryption interface
type AesCtrHmacSha256 struct {
	*hash.Hash
}

func (a *AesCtrHmacSha256) getKeys(key []byte) (encKey, hmacKey, iv []byte) {
	// Derive keys
	keys := a.DeriveKey(key, []byte(hkdfInfo), hkdfLength)
	iv = utils.RandomBytes(ivLength)

	return keys[:encLength], keys[encLength:], iv
}

// Encrypt uses key to encrypt the input plaintext with AES-CTR-Encrypt-then-HMAC-SHA2-256
func (a *AesCtrHmacSha256) Encrypt(key, plaintext []byte) []byte {
	// Derive keys
	encKey, hmacKey, iv := a.getKeys(key)

	// Build the cipher text
	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, plaintext)

	ivc := append(iv, ciphertext...)

	// Calculate hmac
	mac := a.Hmac(ivc, hmacKey)

	return append(ivc, mac...)
}

func split(aead []byte, tagPos int) (iv, ciphertext, mac []byte) {
	//
	iv = aead[:ivLength]
	ciphertext = aead[ivLength:tagPos]
	mac = aead[tagPos:]

	return iv, ciphertext, mac
}

// Decrypt uses key to decrypt the encrypted input with AES-CTR-Encrypt-then-HMAC-SHA2-256
func (a *AesCtrHmacSha256) Decrypt(key, encrypted []byte) ([]byte, error) {
	if len(encrypted) <= (a.OutputSize() + ivLength) {
		return nil, fmt.Errorf("encrypted input is too short (%d), should be %d", len(encrypted), a.OutputSize()+ivLength)
	}

	// Derive keys
	encKey, hmacKey, _ := a.getKeys(key)

	// Split
	tagPos := len(encrypted) - a.OutputSize()
	iv, ciphertext, mac := split(encrypted, tagPos)

	// Verify the tag is correct
	tag := a.Hmac(encrypted[:tagPos], hmacKey)
	if !hmac.Equal(mac, tag) {
		return nil, errors.New("invalid mac on cipher text")
	}

	// Decrypt
	block, err := aes.NewCipher(encKey)
	if err != nil {
		panic(err)
	}

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	return plaintext, nil
}
