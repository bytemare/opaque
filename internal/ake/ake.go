// Package ake provides authenticated key exchange mechanisms
package ake

import (
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup"
	sigma "github.com/bytemare/opaque/internal/ake/internal/sigma-i"
	"github.com/bytemare/opaque/internal/signature"
	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

// Identifier designates registered authenticated key exchange mechanisms
type Identifier byte

const (
	// SigmaI identifies the Sigma-I protocol
	SigmaI Identifier = iota + 1
)

// KeyExchange is an abstraction to underlying key exchange protocols that should implement stage identification
type KeyExchange interface {

	// Kex is the entry point to the protocol engine
	Kex(stage message.Identifier, kex *message.Kex) (sessionKey []byte, response *message.Kex, err error)

	// SetSignature furnishes a Signature engine to the already instantiated and maybe running KeyExchange
	SetSignature(sig signature.Signature)

	// SetPeerPublicKey sets the peer's public key to be used for signature verification
	SetPeerPublicKey(publicKey []byte)
}

type newAKE func(role pake.Role, group hashtogroup.Ciphersuite, hash hash.Identifier, sig signature.Signature, id, peerID []byte) KeyExchange

var ake = make(map[Identifier]newAKE)

func (i Identifier) Get(role pake.Role, group hashtogroup.Ciphersuite, hash hash.Identifier, sig signature.Signature, id, peerID []byte) KeyExchange {
	return ake[i](role, group, hash, sig, id, peerID)
}

func newSigmaI() newAKE {
	return func(role pake.Role, group hashtogroup.Ciphersuite, hash hash.Identifier, sig signature.Signature, id, peerID []byte) KeyExchange {
		return sigma.New(role, group, hash, sig, id, peerID)
	}
}

func init() {
	ake[SigmaI] = newSigmaI()
}
