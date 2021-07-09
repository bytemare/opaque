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

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

// Server exposes the server's AKE functions and holds its state.
type Server struct {
	clientMac     []byte
	sessionSecret []byte

	// testing: integrated to support testing, to force values.
	esk    group.Scalar
	nonceS []byte
}

func NewServer() *Server {
	return &Server{}
}

// SetValues - testing: integrated to support testing, to force values.
// There's no effect if esk, epk, and nonce have already been set in a previous call.
func (s *Server) SetValues(cs ciphersuite.Identifier, esk group.Scalar, nonce []byte, nonceLen int) group.Element {
	g := cs.Get()

	es, nonce := setValues(g, esk, nonce, nonceLen)
	if s.esk == nil || (esk != nil && s.esk != es) {
		s.esk = es
	}

	if s.nonceS == nil {
		s.nonceS = nonce
	}

	return g.Base().Mult(s.esk)
}

// Response produces a 3DH server response message.
func (s *Server) Response(p *internal.Parameters, serverIdentity []byte, serverSecretKey group.Scalar, clientIdentity, clientPublicKey []byte,
	ke1 *message.KE1, response *cred.CredentialResponse) (*message.KE2, error) {
	epk := s.SetValues(p.AKEGroup, nil, nil, p.NonceLen)
	nonce := s.nonceS
	k := &coreKeys{s.esk, serverSecretKey, ke1.EpkU, clientPublicKey}

	ke2 := &message.KE2{
		CredentialResponse: response,
		NonceS:             nonce,
		EpkS:               encoding.PadPoint(epk.Bytes(), p.AKEGroup),
	}

	macs, sessionSecret, err := core3DH(server, p, k, clientIdentity, serverIdentity, ke1, ke2)
	if err != nil {
		return nil, err
	}

	s.sessionSecret = sessionSecret
	s.clientMac = macs.clientMac
	ke2.Mac = macs.serverMac

	return ke2, nil
}

// SerializeState will return a []byte with the given capacity containing
// internal state of the Server.
func (s *Server) SerializeState(size int) []byte {
	return utils.Concatenate(size, s.clientMac, s.sessionSecret)
}

// DeserializeState will set internal state onto the server. `size` should the
// output of internal.Parameters.MAC.Size()
func (s *Server) DeserializeState(data []byte, size int) error {
	if len(s.clientMac) != 0 || len(s.sessionSecret) != 0 {
		return errors.New("existing state is not nil")
	}

	if len(data) != size*2 {
		return errors.New("invalid byte length")
	}

	s.clientMac = data[:size]
	s.sessionSecret = data[size:]

	return nil
}

// Finalize verifies the authentication tag contained in ke3.
func (s *Server) Finalize(p *internal.Parameters, ke3 *message.KE3) bool {
	return p.MAC.Equal(s.clientMac, ke3.Mac)
}

// SessionKey returns the secret shared session key if a previous call to Finalize() was successful.
func (s *Server) SessionKey() []byte {
	return s.sessionSecret
}
