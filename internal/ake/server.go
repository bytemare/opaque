// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package ake provides high-level functions for the 3DH AKE.
package ake

import (
	"errors"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var errStateNotEmpty = errors.New("existing state is not empty")

// Server exposes the server's AKE functions and holds its state.
type Server struct {
	clientMac     []byte
	sessionSecret []byte

	// testing: integrated to support testing, to force values.
	esk    *group.Scalar
	nonceS []byte
}

// NewServer returns a new, empty, 3DH server.
func NewServer() *Server {
	return &Server{}
}

// SetValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func (s *Server) SetValues(id group.Group, esk *group.Scalar, nonce []byte, nonceLen int) *group.Point {
	es, nonce := setValues(id, esk, nonce, nonceLen)
	if s.esk == nil || (esk != nil && s.esk != es) {
		s.esk = es
	}

	if s.nonceS == nil {
		s.nonceS = nonce
	}

	return id.Base().Mult(s.esk)
}

// Response produces a 3DH server response message.
func (s *Server) Response(p *internal.Parameters, serverIdentity []byte, serverSecretKey *group.Scalar,
	clientIdentity []byte, clientPublicKey *group.Point,
	ke1 *message.KE1, response *cred.CredentialResponse) *message.KE2 {
	epk := s.SetValues(p.Group, nil, nil, p.NonceLen)
	nonce := s.nonceS
	k := &coreKeys{s.esk, serverSecretKey, ke1.EpkU, clientPublicKey}

	ke2 := &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               epk,
	}

	sessionSecret, serverMac, clientMac := core3DH(server, p, k, clientIdentity, serverIdentity, ke1, ke2)
	s.sessionSecret = sessionSecret
	s.clientMac = clientMac
	ke2.Mac = serverMac

	return ke2
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

// Finalize verifies the authentication tag contained in ke3.
func (s *Server) Finalize(p *internal.Parameters, ke3 *message.KE3) bool {
	return p.MAC.Equal(s.clientMac, ke3.Mac)
}

// SessionKey returns the secret shared session key if a previous call to Response() was successful.
func (s *Server) SessionKey() []byte {
	return s.sessionSecret
}

// ExpectedMAC returns the expected client MAC if a previous call to Response() was successful.
func (s *Server) ExpectedMAC() []byte {
	return s.clientMac
}
