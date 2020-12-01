// Package sigmai implements the Sigma-I Authenticated Key Exchange protocol for use within OPAQUE
package sigmai

import (
	"fmt"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/hashtogroup"
	"github.com/bytemare/cryptotools/hashtogroup/group"
	"github.com/bytemare/opaque/internal/envelope/authenc"
	"github.com/bytemare/opaque/internal/signature"

	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

const (
	dsiSigning    = "SigmaI-EncryptionKey"
	dsiEncryption = "SigmaI-MacKey"
	dsiSessionKey = "SigmaI-SessionKey"

	protocol = "Sigma-I"
	version  = "0.0.0"

	keyLength = 32
)

// SigmaI holds handshake specific information and state.
type SigmaI struct {
	// Own info
	role pake.Role
	id   []byte
	dh   *dh

	// Peer info
	peer peer

	// shared info
	sk *sigmaIkeys

	// Cryptographic engines
	sig   signature.Signature // todo : this is sensitive, and should be cleared from memory after use
	group group.Group
	hash  *hash.Hash
	rkr   authenc.RKRAuthenticatedEncryption
}

type peer struct {
	id, pubkey []byte
}

type sigmaIkeys struct {
	ke, km, sessionKey []byte
}

// New initialises and returns a new SigmaI structure.
func New(role pake.Role, suite hashtogroup.Ciphersuite, hash hash.Identifier, sig signature.Signature, id, peerID []byte) *SigmaI {
	dst, err := suite.MakeDST(protocol, version)
	if err != nil {
		panic(err)
	}

	g := suite.Get(dst)

	s := &SigmaI{
		role:  role,
		id:    id,
		dh:    new(dh),
		peer:  peer{id: peerID, pubkey: nil},
		sk:    new(sigmaIkeys),
		sig:   sig,
		group: g,
		hash:  hash.Get(),
		rkr:   authenc.New(authenc.Default),
	}

	s.initDH(nil)

	return s
}

// Kex is the API to operate the key exchange through. The state parameter should indicate at what stage the key exchange
// is, and kex is the message. If the peer calling this method needs to send back a message to complete the protocol,
// this message will be returned by response. If the key exchange is successful for the calling peer, this function will
// also return the resulting session key.
//
// The very first call, usually the initiator or client, should indicate message.StageStart for stage, and nil for kex to
// trigger the protocol.
//
// At any stage, if inconsistent input is given the function will panic, since it's a misuse of the implementation. For
// errors triggered by a peer message, an error is returned and nothing else.
func (s *SigmaI) Kex(stage message.Identifier, kex *message.Kex) (sessionKey []byte, response *message.Kex, err error) {
	// if both peerExp and peerEncrypted are nil, it's the initiator starting the key exchange
	if kex == nil || kex.Element == nil && kex.Auth == nil {
		if stage != message.StageStart {
			panic("Initiating Key exchange, stage should be sigma start")
		}

		switch s.role {
		case pake.Initiator:
			// Start the protocol
			return nil, &message.Kex{Element: s.dh.exp}, err
		case pake.Responder:
			panic("can't initiate Sigma-I if not Initiator (message is nil)")
		}
	}

	// By now, the private key must have been set
	if s.sig == nil {
		panic("signature not set. Have you SetSignature() before this ?")
	}

	switch stage {
	case message.StageResponse:
		return s.response(kex)
	case message.StageAuth:
		return s.finish(kex)
	}

	return nil, nil, fmt.Errorf("invalid sigma stage '%v'", stage)
}

// SetSignature specifies the Signature to use for signing operations.
func (s *SigmaI) SetSignature(sig signature.Signature) {
	s.sig = sig
}

// SetPeerPublicKey sets the peer's public key to use for signature verification.
func (s *SigmaI) SetPeerPublicKey(publicKey []byte) {
	s.peer.pubkey = make([]byte, 0, len(publicKey))
	s.peer.pubkey = append(s.peer.pubkey, publicKey...)
}

// response is only called by the responder.
func (s *SigmaI) response(kex *message.Kex) (sessionKey []byte, response *message.Kex, err error) {
	// Finishes the Diffie-Hellman setup to derive the keys
	if err := s.finishDH(kex.Element); err != nil {
		return nil, nil, err
	}

	authentication, err := s.encryptedResponse()
	if err != nil {
		return nil, nil, err
	}

	// Don't return the session key just yet, as weed need another client message for explicit authentication
	return nil, &message.Kex{
		Element: s.dh.exp,
		Auth:    authentication,
	}, nil
}

func (s *SigmaI) finish(kex *message.Kex) (sessionKey []byte, response *message.Kex, err error) {
	// First, use the peer's exp to derive the keys
	if s.role == pake.Initiator {
		if err := s.finishDH(kex.Element); err != nil {
			return nil, nil, err
		}
	}

	// Verify the peer's message
	// If signature or mac fail, abort
	if err := s.verify(kex.Auth); err != nil {
		return nil, nil, err
	}

	// The responder has verified the client, and therefore returns the session key
	if s.role == pake.Responder {
		return s.sk.sessionKey, nil, nil
	}

	// The initiator must send a message back to the server to terminate
	// explicit authentication by finishing the Diffie-Hellman key exchange
	authentication, err := s.encryptedResponse()
	if err != nil {
		return nil, nil, err
	}

	// Only the responder sends its element in a response
	return s.sk.sessionKey, &message.Kex{Auth: authentication}, nil
}
