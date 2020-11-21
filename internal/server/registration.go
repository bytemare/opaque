// Package server implements the server-side protocol of OPAQUE
package server

import (
	"fmt"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/pake/message"
)

func (s *Server) startRegistration(p *message.OPRFInit) ([]byte, error) {
	m, err := s.oprfResponse(p.InitBlind)
	if err != nil {
		return nil, err
	}

	s.Expect = message.RegisterFinish

	return m.Encode(s.Encoding())
}

func (s *Server) finishRegistration(p *message.Registration) error {
	var verifier internal.RegistrationPayload

	_, err := s.Encoding().Decode(p.Verifier, &verifier)
	if err != nil {
		return fmt.Errorf("decoding verifier : %w", err)
	}

	s.user.PubU = verifier.PublicKey
	s.user.Envelope = verifier.Envelope

	s.Expect = message.StageTerminated

	return nil
}
