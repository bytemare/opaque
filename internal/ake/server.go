// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package ake

import (
	"errors"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
)

var errStateNotEmpty = errors.New("existing state is not empty")

// Server exposes the server's AKE functions and holds its state.
type Server struct {
	clientMac     []byte
	sessionSecret []byte
}

// NewServer returns a new, empty, 3DH server.
func NewServer() *Server {
	return &Server{
		clientMac:     nil,
		sessionSecret: nil,
	}
}

// Response produces a 3DH server response message.
func (s *Server) Response(
	conf *internal.Configuration,
	ke1 *message.KE1,
	response *message.CredentialResponse,
	serverKM, clientKM *KeyMaterial,
) *message.KE2 {
	// epk, nonce := s.getOptions(conf.Group, options)

	ke2 := &message.KE2{
		CredentialResponse:   response,
		ServerNonce:          serverKM.Nonce,
		ServerPublicKeyshare: serverKM.PublicKeyShare,
		ServerMac:            nil,
	}

	ikm := k3dh(
		clientKM.PublicKeyShare,
		serverKM.EphemeralSecretKey,
		clientKM.PublicKeyShare,
		serverKM.SecretKey,
		clientKM.PublicKey,
		serverKM.EphemeralSecretKey,
	)

	sessionSecret, serverMac, clientMac := core3DH(
		conf,
		clientKM.Identity,
		serverKM.Identity,
		ikm,
		ke1.Serialize(),
		ke2,
	)
	s.sessionSecret = sessionSecret
	s.clientMac = clientMac
	ke2.ServerMac = serverMac

	return ke2
}

func MakeKeyMaterial2(
	id, nonce []byte,
	ephemeralSecretKey, secretKey *ecc.Scalar,
	publicKeyShare *ecc.Element,
) *KeyMaterial {
	return &KeyMaterial{
		Identity:           id,
		Nonce:              nonce,
		EphemeralSecretKey: ephemeralSecretKey,
		PublicKeyShare:     publicKeyShare,
		SecretKey:          secretKey,
		PublicKey:          nil,
	}
}

func MakePeerKeyMaterial(id []byte, peerPublicKeyShare, peerPublicKey *ecc.Element) *KeyMaterial {
	return &KeyMaterial{
		Identity:           id,
		EphemeralSecretKey: nil,
		PublicKeyShare:     peerPublicKeyShare,
		SecretKey:          nil,
		PublicKey:          peerPublicKey,
	}
}

func MakeKeyMaterial(
	ephemeralSecretKey, secretKey *ecc.Scalar,
	peerPublicKeyShare, peerPublicKey *ecc.Element,
) (*KeyMaterial, *KeyMaterial) {
	own := &KeyMaterial{
		Identity:           nil,
		EphemeralSecretKey: ephemeralSecretKey,
		PublicKeyShare:     nil,
		SecretKey:          secretKey,
		PublicKey:          nil,
	}

	peer := &KeyMaterial{
		Identity:           nil,
		EphemeralSecretKey: nil,
		PublicKeyShare:     peerPublicKeyShare,
		SecretKey:          nil,
		PublicKey:          peerPublicKey,
	}

	return own, peer
}

func KeyMaterialForClient(
	i *Identities,
	ephemeralSecretKey, secretKey *ecc.Scalar,
	serverPublicKeyShare, serverPublicKey *ecc.Element,
) (*KeyMaterial, *KeyMaterial) {
	client, server := MakeKeyMaterial(ephemeralSecretKey, secretKey, serverPublicKeyShare, serverPublicKey)
	client.Identity = i.ClientIdentity
	server.Identity = i.ServerIdentity

	return client, server
}

func KeyMaterialForServer(
	i *Identities,
	ephemeralSecretKey, secretKey *ecc.Scalar,
	clientPublicKeyShare, clientPublicKey *ecc.Element,
) (*KeyMaterial, *KeyMaterial) {
	server, client := MakeKeyMaterial(ephemeralSecretKey, secretKey, clientPublicKeyShare, clientPublicKey)
	server.Identity = i.ServerIdentity
	client.Identity = i.ClientIdentity

	return server, client
}

type KeyMaterial struct {
	EphemeralSecretKey *ecc.Scalar
	PublicKeyShare     *ecc.Element
	SecretKey          *ecc.Scalar
	PublicKey          *ecc.Element
	Identity           []byte
	Nonce              []byte
}

// Finalize verifies the authentication tag contained in ke3.
func (s *Server) Finalize(conf *internal.Configuration, ke3 *message.KE3) (bool, []byte) {
	return conf.MAC.Equal(s.clientMac, ke3.ClientMac), s.clientMac
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
	s.clientMac = nil
	s.sessionSecret = nil
}
