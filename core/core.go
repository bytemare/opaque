package core

import (
	"fmt"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

type Core struct {
	Group ciphersuite.Identifier
	Oprf  *voprf.Client

	envelope.Mode
	*envelope.Keys
}

// todo: this is for testing. Delete later.
func (c *Core) DebugGetKeys() (pad, authKey, exportKey, prk []byte) {
	return c.Pad, c.AuthKey, c.ExportKey, c.Prk
}

func NewCore(suite voprf.Ciphersuite, kdf *internal.KDF, mac *internal.Mac, h *internal.Hash, m *mhf.MHF, mode envelope.Mode, g group.Group) *Core {
	oprf, err := suite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Group: suite.Group(),
		Oprf:  oprf,
		Mode:  mode,
		Keys:  envelope.NewKeys(g, kdf, mac, h, m),
	}
}

func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

func (c *Core) oprfFinalize(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.Oprf.Finalize(ev)
}

func (c *Core) BuildEnvelope(evaluation, pks []byte, creds *envelope.Credentials) (*envelope.Envelope, []byte, error) {
	unblinded, err := c.oprfFinalize(evaluation)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	return c.Keys.BuildEnvelopeNew(unblinded, pks, c.Mode, creds)
}

func (c *Core) RecoverSecret(idu, ids, pks, evaluation []byte, envU *envelope.Envelope) (*envelope.SecretCredentials, []byte, error) {
	unblinded, err := c.oprfFinalize(evaluation)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	return c.Keys.RecoverSecretNew(idu, ids, pks, unblinded, envU)
}
