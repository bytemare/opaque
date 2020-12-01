// Package server implements the server-side protocol of OPAQUE.
package server

import (
	"errors"

	"github.com/bytemare/cryptotools"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/record"
	"github.com/bytemare/voprf"

	"github.com/bytemare/pake"
	"github.com/bytemare/pake/message"
)

// SetUserRecord is used by the server to load the input record matching the client to authenticate.
func (s *Server) SetUserRecord(rec interface{}) error {
	var ok bool

	s.user, ok = rec.(*record.UserRecord)
	if !ok {
		panic("invalid type for user record")
	}

	s.Signature.LoadKey(s.user.ServerPrivateKey)

	if s.Mode() == pake.KeyExchange {
		// Now that we have the user information, we can instantiate the key exchange engine
		s.Kex = ake.SigmaI.Get(pake.Responder, s.Crypto.Parameters.Group, s.Crypto.Parameters.Hash, s.Signature, s.Encoding(), s.Sni, s.user.Username)
	}

	// The user record contains the associated OPRF private key
	sks, err := s.Crypto.NewScalar().Decode(s.user.PrivateOPRFKey)
	if err != nil {
		panic(err)
	}

	o, err := voprf.FromHashToGroup(s.Crypto.Parameters.Group)
	if err != nil {
		return err
	}

	s.OPRF, err = o.Server(sks.Bytes())
	if err != nil {
		return err
	}

	return nil
}

// Register is the API to use during the message exchange for client registration.
func (s *Server) Register(m []byte) ([]byte, error) {
	return s.registration(m)
}

// Authenticate is the API to use during the message exchange for authenticated key exchange.
func (s *Server) Authenticate(m []byte) ([]byte, error) {
	return s.keyExchange(m)
}

// SessionKey returns the session key if the authenticated key exchange was successful.
func (s *Server) SessionKey() []byte {
	return s.sessionKey
}

// EncodedParameters returns the 4-byte encoding of the ciphersuite parameters.
func (s *Server) EncodedParameters() cryptotools.CiphersuiteEncoding {
	return s.Crypto.Parameters.Encode()
}

func (s *Server) verify(m []byte) (interface{}, error) {
	if s.Expect == message.StageTerminated {
		return nil, errors.New("the procedure should have been terminated")
	}

	if m == nil {
		panic("server can't handle nil message")
	}

	if s.user == nil {
		panic("no user record set")
	}

	// Validate and decode the payload
	return s.Expect.Decode(m, s.Encoding())
}

func (s *Server) registration(m []byte) ([]byte, error) {
	payload, err := s.verify(m)
	if err != nil {
		return nil, err
	}

	switch s.Expect {
	case message.RegisterStart:
		return s.startRegistration(payload.(*message.OPRFInit))

	case message.RegisterFinish:
		return nil, s.finishRegistration(payload.(*message.Registration))
	default:
		panic("invalid stage expectation")
	}
}

func (s *Server) keyExchange(m []byte) ([]byte, error) {
	payload, err := s.verify(m)
	if err != nil {
		return nil, err
	}

	switch s.Expect {
	case message.StageStart:
		return s.response(payload.(*message.Start))

	case message.StageAuth:
		return nil, s.authentication(payload.(*message.ExplicitAuth))

	default:
		panic("invalid stage expectation")
	}
}
