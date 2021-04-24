package core

import (
	"fmt"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal/parameters"
	"github.com/bytemare/voprf"
)

type Core struct {
	Group ciphersuite.Identifier
	Oprf  *voprf.Client

	*envelope.Thing
}

func NewCore(parameters *parameters.Parameters, mode envelope.Mode) *Core {
	oprf, err := parameters.OprfCiphersuite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Group: parameters.OprfCiphersuite.Group(),
		Oprf:  oprf,
		Thing: envelope.NewThing(parameters, mode),
	}
}

func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

func (c *Core) OprfFinalize(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.Oprf.Finalize(ev)
}

func (c *Core) BuildEnvelope(evaluation, pks, skc []byte, creds *envelope.Credentials) (env *envelope.Envelope, pkc, maskingKey, exportKey []byte, err error) {
	unblinded, err := c.OprfFinalize(evaluation)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := c.Thing.BuildPRK(unblinded, nil)
	env, pkc, maskingKey, exportKey = c.Thing.CreateEnvelope(randomizedPwd, pks, skc, creds)

	return env, pkc, maskingKey, exportKey, nil
}

func (c *Core) RecoverSecret(idc, ids, pks, randomizedPwd []byte, envU *envelope.Envelope) (skc, pkc, exportKey []byte, err error) {
	creds := &envelope.Credentials{
		Idc: idc,
		Ids: ids,
	}

	return c.Thing.RecoverEnvelope(randomizedPwd, pks, creds, envU)
}
