// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ake

import (
	"errors"

	group "github.com/bytemare/crypto"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

var errStateNotEmpty = errors.New("existing state is not empty")

// Server exposes the server's AKE functions and holds its state.
type Server struct {
	values
	clientMac     []byte
	sessionSecret []byte
}

// NewServer returns a new, empty, 3DH server.
func NewServer() *Server {
	return &Server{
		values: values{
			ephemeralSecretKey: nil,
			nonce:              nil,
		},
		clientMac:     nil,
		sessionSecret: nil,
	}
}

// Response produces a 3DH server response message.
func (s *Server) Response(
	conf *internal.Configuration,
	identities *Identities,
	serverSecretKey *group.Scalar,
	clientPublicKey *group.Element,
	ke1 *message.KE1,
	response *message.CredentialResponse,
	options Options,
) *message.KE2 {
	epk := s.values.setOptions(conf.Group, options)

	ke2 := &message.KE2{
		CredentialResponse: response,
		NonceS:             s.nonce,
		EpkS:               epk,
		Mac:                nil,
	}

	ikm := k3dh(
		ke1.EpkU,
		s.ephemeralSecretKey,
		ke1.EpkU,
		serverSecretKey,
		clientPublicKey,
		s.ephemeralSecretKey,
	)
	sessionSecret, serverMac, clientMac := core3DH(conf, identities, ikm, ke1.Serialize(), ke2)
	s.sessionSecret = sessionSecret
	s.clientMac = clientMac
	ke2.Mac = serverMac

	return ke2
}

// Finalize verifies the authentication tag contained in ke3.
func (s *Server) Finalize(conf *internal.Configuration, ke3 *message.KE3) bool {
	return conf.MAC.Equal(s.clientMac, ke3.Mac)
}

// SessionKey returns the secret shared session key if a previous call to Response() was successful.
func (s *Server) SessionKey() []byte {
	return s.sessionSecret
}

// ExpectedMAC returns the expected client MAC if a previous call to Response() was successful.
func (s *Server) ExpectedMAC() []byte {
	return s.clientMac
}

// SerializeState will return a []byte containing internal state of the Server.
func (s *Server) SerializeState() []byte {
	state := make([]byte, len(s.clientMac)+len(s.sessionSecret))

	i := copy(state, s.clientMac)
	copy(state[i:], s.sessionSecret)

	return state
}

// SetState will set the given clientMac and sessionSecret in the server's internal state.
func (s *Server) SetState(clientMac, sessionSecret []byte) error {
	if len(s.clientMac) != 0 || len(s.sessionSecret) != 0 {
		return errStateNotEmpty
	}

	s.clientMac = clientMac
	s.sessionSecret = sessionSecret

	return nil
}

// Flush sets all the server's session related internal AKE values to nil.
func (s *Server) Flush() {
	s.ephemeralSecretKey.Zero()
	s.ephemeralSecretKey = nil
	s.nonce = nil
	s.clientMac = nil
	s.sessionSecret = nil
}
