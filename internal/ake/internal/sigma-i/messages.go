// Package sigmai implements the Sigma-I Authenticated Key Exchange protocol for use within OPAQUE
package sigmai

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
)

type auth struct {
	ID  id
	Sig []byte
	Mac []byte
}

type id struct {
	ID        []byte
	PublicKey []byte
}

func (s *SigmaI) encryptedResponse() ([]byte, error) {
	// Build the sub message and encrypt it
	sm := auth{
		ID: id{
			ID:        s.id,
			PublicKey: s.sig.GetPublicKey(),
		},
		Sig: s.sig.Sign(s.dh.peerExp, s.dh.exp),
		Mac: s.hash.Hmac(s.id, s.sk.km),
	}

	return s.encryptSubMessage(&sm)
}

func (s *SigmaI) encryptSubMessage(sm *auth) ([]byte, error) {
	e, err := s.encoding.Encode(sm)
	if err != nil {
	}

	// encrypt
	return s.rkr.Encrypt(s.sk.ke, e), nil
}

func (s *SigmaI) decryptSubMessage(m []byte) (*auth, error) {
	// decrypt
	p, err := s.rkr.Decrypt(s.sk.ke, m)
	if err != nil {
		return nil, err
	}

	// decode
	d, err := s.encoding.Decode(p, &auth{})
	if err != nil {
		return nil, err
	}

	sm, ok := d.(*auth)
	if !ok {
		return nil, errors.New("failed to assert type on decoded sub message")
	}

	return sm, nil
}

// verify checks whether the mac and signature are valid.
func (s *SigmaI) verify(encryptedSubMessage []byte) error {
	// First check we have everything we need
	if s.peer.pubkey == nil {
		panic("peer's public key hasn't been set. Have you SetPeerPublicKey() before this ?")
	}

	// Decrypt the sub message
	sm, err := s.decryptSubMessage(encryptedSubMessage)
	if err != nil {
		return fmt.Errorf("sub-message decryption failed : %q", err)
	}

	// Verify if peer-sent info matches what we want
	if !bytes.Equal(sm.ID.ID, s.peer.id) {
		return fmt.Errorf("sigma-i: peer sent ID '%v' doesn't match '%v'", sm.ID.ID, s.peer.id)
	}

	if !bytes.Equal(sm.ID.PublicKey, s.peer.pubkey) {
		return errors.New("sigma-i: peer sent public key doesn't match")
	}

	// Verify mac
	pmac := s.hash.Hmac(s.peer.id, s.sk.km)
	if !hmac.Equal(pmac, sm.Mac) {
		return errors.New("sigma-i: invalid peer mac")
	}

	// Verify signature
	ms := append(s.dh.exp, s.dh.peerExp...)
	if !s.sig.Verify(s.peer.pubkey, ms, sm.Sig) {
		return errors.New("sigma-i: invalid peer signature")
	}

	return nil
}
