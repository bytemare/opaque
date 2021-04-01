package core

import (
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

type Core struct {
	Group ciphersuite.Identifier
	Oprf  *voprf.Client

	*envelope.Thing
}

func NewCore(suite voprf.Ciphersuite, kdf *internal.KDF, mac *internal.Mac, mhf *internal.MHF, mode envelope.Mode, akeGroup ciphersuite.Identifier, nonceLen int) *Core {
	oprf, err := suite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Group: suite.Group(),
		Oprf:  oprf,
		Thing: envelope.NewThing(akeGroup, kdf, mac, mhf, mode, nonceLen),
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

	prk := c.Thing.BuildPRK(unblinded, nil)
	env, pkc, maskingKey, exportKey = c.Thing.CreateEnvelope(prk, pks, skc, creds)

	return env, pkc, maskingKey, exportKey, nil
}

func (c *Core) RecoverSecret(idc, ids, pks, prk []byte, envU *envelope.Envelope) (sc *envelope.SecretCredentials, pkc, exportKey []byte, err error) {
	creds := &envelope.Credentials{
		Idc: idc,
		Ids: ids,
	}

	return c.Thing.RecoverEnvelope(prk, pks, creds, envU)
}
