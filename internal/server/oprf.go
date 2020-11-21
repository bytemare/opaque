// Package server implements the server-side protocol of OPAQUE
package server

import "github.com/bytemare/pake/message"

func (s *Server) oprfResponse(alpha []byte) (*message.OPRFResponse, error) {
	if s.user == nil {
		panic("no user record was set")
	}

	// Calculate Beta = f (alpha, kU)
	beta, err := s.OPRF.Evaluate(alpha)
	if err != nil {
		return nil, err
	}

	ev, err := beta.Encode(s.Encoding())
	if err != nil {
		return nil, err
	}

	or := &message.OPRFResponse{
		RespBlind:     ev,
		PublicOPRFKey: s.user.PublicOPRFKey,
	}

	// We send the server public key on registration, that the client will set in the envelope
	if s.Expect == message.RegisterStart {
		or.Extra = s.Signature.GetPublicKey()
	}

	// Send back pubS, salt2/V, Beta - OPAQUE assumes an attacker is able to recover those
	return or, nil
}
