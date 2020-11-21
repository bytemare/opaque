// Package sigmai implements the Sigma-I Authenticated Key Exchange protocol for use within OPAQUE
package sigmai

import (
	"fmt"

	"github.com/bytemare/cryptotools/hashtogroup/group"
)

type dh struct {
	secret       group.Scalar
	exp, peerExp []byte
}

func (s *SigmaI) initDH(generator []byte) {
	s.dh.secret = s.group.NewScalar().Random()

	if generator != nil {
		g, err := s.group.NewElement().Decode(generator)
		if err != nil {
			panic(err)
		}

		s.dh.exp = g.Mult(s.dh.secret).Bytes()
	} else {
		s.dh.exp = s.group.Base().Mult(s.dh.secret).Bytes()
	}
}

func (s *SigmaI) finishDH(peerExp []byte) error {
	// build the session key
	sharedSecret, err := s.buildKey(peerExp)
	if err != nil {
		return err
	}
	// Now that the shared secret is set, we can derive encryption keys
	s.deriveKeys(sharedSecret)

	return nil
}

func (s *SigmaI) buildKey(peerExp []byte) ([]byte, error) {
	var err error

	pe, err := s.group.NewElement().Decode(peerExp)
	if err != nil {
		return nil, fmt.Errorf("invalid peer element : %w", err)
	}

	s.dh.peerExp = pe.Bytes()

	sharedSecret := pe.Mult(s.dh.secret).Bytes()

	return sharedSecret, nil
}

func (s *SigmaI) deriveKeys(sharedSecret []byte) {
	s.sk.ke = s.hash.HKDF(sharedSecret, nil, []byte(dsiEncryption), keyLength)
	s.sk.km = s.hash.HKDF(sharedSecret, nil, []byte(dsiSigning), keyLength)
	s.sk.sessionKey = s.hash.HKDF(sharedSecret, nil, []byte(dsiSessionKey), keyLength)
}
