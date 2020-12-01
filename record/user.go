// Package record provides utilities for working with user records in OPAQUE
package record

import (
	"github.com/bytemare/cryptotools"
)

const (
	protocol = "OPAQUE"
	version  = "0.0.0"
)

// UserRecord implements the user record as specified in the OPAQUE I-D.
type UserRecord struct {
	// Username defines a unique user identifying element
	Username []byte

	// PubU is the user's associated public key
	PubU []byte

	// Envelope is the the user's sealed secrets, usually contained the user's private key
	Envelope []byte

	// PrivateOPRFKey (a.k.a k) is the per-user, independent, random, committed OPRF private key
	PrivateOPRFKey []byte

	// PublicOPRFKey (a.k.a. V or vU) is the associated committed OPRF public key
	PublicOPRFKey []byte

	// ServerPrivateKey is the server's private key for key agreement.
	// If this key is used for multiple users, the server can store these values (private and public key)
	// separately and omit them from the user's record.
	ServerPrivateKey []byte
}

// NewUserRecord provides a quick way to create a user entry.
// Todo : this is for the POC. A proper way to handle user records must be implemented.
func NewUserRecord(username, serverPrivateKey []byte, csp *cryptotools.Parameters) (*UserRecord, error) {
	dst, err := csp.Group.MakeDST(protocol, version)
	if err != nil {
		panic(err)
	}

	c, err := cryptotools.New(csp, dst)
	if err != nil {
		return nil, err
	}

	serverSalt := c.NewScalar().Random()

	vu := c.Base().Mult(serverSalt)

	return &UserRecord{
		Username:         username,
		PubU:             nil,
		Envelope:         nil,
		PrivateOPRFKey:   serverSalt.Bytes(),
		PublicOPRFKey:    vu.Bytes(),
		ServerPrivateKey: serverPrivateKey,
	}, nil
}
