// Package opaque implements the OPAQUE asymmetric password authenticated key exchange (aPAKE) protocol
package opaque

import (
	"errors"

	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/voprf"

	"github.com/bytemare/pake"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/client"
	"github.com/bytemare/opaque/internal/envelope/authenc"
	"github.com/bytemare/opaque/internal/server"
)

// Mode is a pake.Mode alias.
type Mode pake.Mode

const (
	Registration   = Mode(pake.Registration)
	Authentication = Mode(pake.KeyExchange)

	protocol = "OPAQUE"
	version  = "0.0.0"
)

// Parameters groups a party's input parameters.
type Parameters struct {
	// SNI
	SNI []byte

	// UserID
	UserID []byte

	// Secret
	Secret []byte

	// Encoding
	Encoding encoding.Encoding
}

// New returns an OPAQUE asymmetric PAKE (Password Authenticated Key Exchange) interface.
//
// The role should be one of Client or Server.
// The cryptographic engine is configured through the ciphersuite parameters, and can be nil to use the defaults.
// sni identifies the server (server name indication), and username the client.
// username is not used when creating a server, and a user record MUST be added before engaging in a response.
// secret defines either the user password or the server's private key's seed.
func newOpaque(mode pake.Mode, role pake.Role, parameters *Parameters, csp *cryptotools.Parameters) (*internal.Opaque, error) {
	// todo : add missing argument checks
	core, err := mode.New(protocol, version, parameters.Encoding, csp, role, parameters.SNI)
	if err != nil {
		return nil, err
	}

	return &internal.Opaque{
		Core:                       core,
		RKRAuthenticatedEncryption: authenc.New(authenc.Default),
		Kex:                        nil,
	}, nil
}

func (m Mode) Client(parameters *Parameters, csp *cryptotools.Parameters) (pake.AugmentedPake, error) {
	if len(parameters.UserID) == 0 {
		return nil, errors.New("username cannot be empty or nil")
	}

	if len(parameters.Secret) == 0 {
		return nil, errors.New("secret/password can not be empty or nil")
	}

	opaque, err := newOpaque(pake.Mode(m), pake.Initiator, parameters, csp)
	if err != nil {
		return nil, err
	}

	op, err := voprf.FromHashToGroup(opaque.Core.Crypto.Parameters.Group)
	if err != nil {
		return nil, err
	}

	oprf, err := op.Client(nil)
	if err != nil {
		return nil, err
	}

	return client.New(parameters.UserID, parameters.Secret, oprf, opaque), nil
}

func (m Mode) Server(parameters *Parameters, csp *cryptotools.Parameters) (pake.AugmentedPake, error) {
	o, err := newOpaque(pake.Mode(m), pake.Responder, parameters, csp)
	if err != nil {
		return nil, err
	}

	return server.New(o), nil
}
