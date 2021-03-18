package core

import (
	"errors"
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

func NewCore(suite voprf.Ciphersuite, kdf *internal.KDF, mac *internal.Mac, mhf *internal.MHF, mode envelope.Mode, akeGroup ciphersuite.Identifier) *Core {
	oprf, err := suite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Group: suite.Group(),
		Oprf:  oprf,
		Thing: envelope.NewThing(akeGroup, kdf, mac, mhf, mode),
	}
}

func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

func (c *Core) oprfFinalize(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.Oprf.Finalize(ev)
}

func (c *Core) checks(creds *envelope.Credentials) error {
	switch c.Mode {
	case envelope.Internal:
		if creds.Skx != nil {
			return errors.New("a secret key was provided in internal mode")
		}

		if creds.Pkc != nil {
			return errors.New("a public key was provided in internal mode")
		}
	case envelope.External:
		if len(creds.Skx) != internal.ScalarLength(c.Thing.Identifier) {
			return errors.New("invalid secret key secret key length")
		}

		if len(creds.Pkc) != internal.PointLength(c.Thing.Identifier) {
			return errors.New("invalid secret key public key length")
		}
	default:
		return errors.New("invalid envelope mode")
	}

	return nil
}

func (c *Core) BuildEnvelope(evaluation, pks []byte, creds *envelope.Credentials) (*envelope.Envelope, []byte, []byte, error) {
	if err := c.checks(creds); err != nil {
		return nil, nil, nil, err
	}

	unblinded, err := c.oprfFinalize(evaluation)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	env, pkc, exportKey := c.Thing.CreateEnvelope(unblinded, pks, creds)

	return env, pkc, exportKey, nil
}

func (c *Core) RecoverSecret(idc, ids, pkc, pks, evaluation []byte, envU *envelope.Envelope) (*envelope.SecretCredentials, []byte, error) {
	unblinded, err := c.oprfFinalize(evaluation)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	creds := &envelope.Credentials{
		Pkc: pkc,
		Idc: idc,
		Ids: ids,
	}

	return c.Thing.RecoverSecret(unblinded, pks, creds, envU)
}
