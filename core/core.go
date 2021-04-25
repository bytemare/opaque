package core

import (
	"fmt"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/parameters"
	"github.com/bytemare/voprf"
)

type Core struct {
	Oprf  *voprf.Client
	*parameters.Parameters
}

func NewCore(parameters *parameters.Parameters) *Core {
	oprf, err := parameters.OprfCiphersuite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Oprf:  oprf,
		Parameters: parameters,
	}
}

func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

func (c *Core) OprfFinalize(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.Oprf.Finalize(ev)
}

func (c *Core) BuildEnvelope(mode envelope.Mode, evaluation, pks, skc []byte, creds *envelope.Credentials) (env *envelope.Envelope, pkc, maskingKey, exportKey []byte, err error) {
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



func (c *Core) RecoverSecret(mode envelope.Mode, idc, ids, pks, randomizedPwd []byte, envU *envelope.Envelope) (skc, pkc, exportKey []byte, err error) {
	creds := &envelope.Credentials{
		Idc: idc,
		Ids: ids,
	}

	m := &envelope.Mailer{Parameters: c.Parameters}

	return m.RecoverEnvelope(mode, randomizedPwd, pks, creds, envU)
}
