// Package server implements the server-side protocol of OPAQUE.
package server

import (
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/signature"
	"github.com/bytemare/opaque/record"
	"github.com/bytemare/voprf"
)

// Server implements the Pake interface.
type Server struct {
	// User related data
	user *record.UserRecord

	// Session secrets
	sessionKey []byte

	// OPAQUE protocol engine
	Signature signature.Signature
	OPRF      *voprf.Server
	*internal.Opaque
}

// New returns a pointer to an initialised Server struct.
func New(opaque *internal.Opaque) *Server {
	return &Server{
		Signature: signature.New(signature.Ed25519),
		Opaque:    opaque,
	}
}
