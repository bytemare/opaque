// Package core links OPAQUE's OPRF client functions to envelope creation and key recovery.
package core

import (
	"fmt"

	"github.com/bytemare/voprf"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/core/envelope"
)

// Core holds the Client state between the key derivation steps,
// and exposes envelope creation and key recovery functions.
type Core struct {
	Oprf *voprf.Client
	*internal.Parameters
}

// New returns a pointer to an instantiated Core structure.
func New(parameters *internal.Parameters) *Core {
	oprf, err := parameters.OprfCiphersuite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Oprf:       oprf,
		Parameters: parameters,
	}
}

// OprfStart initiates the OPRF by blinding the password.
func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

// OprfFinalize terminates the OPRF by unblind the evaluated data.
func (c *Core) OprfFinalize(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.Oprf.Finalize(ev)
}

// BuildEnvelope returns the client's Envelope, the masking key for the registration, and the additional export key.
func (c *Core) BuildEnvelope(mode envelope.Mode, evaluation, pks, skc []byte,
	creds *envelope.Credentials) (env *envelope.Envelope, pkc, maskingKey, exportKey []byte, err error) {
	unblinded, err := c.OprfFinalize(evaluation)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := envelope.BuildPRK(c.Parameters, unblinded)
	m := &envelope.Mailer{Parameters: c.Parameters}
	env, pkc, exportKey = m.CreateEnvelope(mode, randomizedPwd, pks, skc, creds)
	maskingKey = m.KDF.Expand(randomizedPwd, []byte(internal.TagMaskingKey), m.KDF.Size())

	return env, pkc, maskingKey, exportKey, nil
}
