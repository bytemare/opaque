// Package server implements the server-side protocol of OPAQUE
package server

import "github.com/bytemare/pake/message"

func (s *Server) response(m *message.Start) ([]byte, error) {
	// build the OPRF response
	or, err := s.oprfResponse(m.InitBlind)
	if err != nil {
		return nil, err
	}

	or.Extra = s.user.Envelope // todo : the draft and paper give indications on how to protect against user enumeration

	// build key exchange response
	s.Kex.SetPeerPublicKey(s.user.PubU)

	_, kex, err := s.Kex.Kex(message.StageResponse, &m.Kex)
	if err != nil {
		return nil, err
	}

	opr := message.Response{
		OPRFResponse: *or,
		Kex:          *kex,
	}

	s.Expect = message.StageAuth

	return opr.Encode(s.Encoding())
}

func (s *Server) authentication(m *message.ExplicitAuth) error {
	sk, _, err := s.Kex.Kex(message.StageAuth, m)
	if err != nil {
		return err
	}

	s.sessionKey = sk

	s.Expect = message.StageTerminated

	return nil
}
