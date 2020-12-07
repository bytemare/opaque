// Package client implements the client-side protocol of OPAQUE
package client

import (
	"github.com/bytemare/voprf"

	"github.com/bytemare/pake/message"
)

func (c *Client) oprfStart() *message.OPRFInit {
	alpha := c.oprf.Blind(c.password)

	return &message.OPRFInit{
		UserID:    c.username,
		InitBlind: alpha,
	}
}

func (c *Client) oprfFinish(p *message.OPRFResponse) ([]byte, error) {
	eval, err := voprf.DecodeEvaluation(p.RespBlind, c.Encoding())
	if err != nil {
		return nil, err
	}

	// todo: define info
	tmp, err := c.oprf.Finalize(eval, nil)
	if err != nil {
		return nil, err
	}

	// Hardening OPRF via pwKDF
	// todo : rwdu is sensitive and must be secured and deleted asap
	rwdU := c.Crypto.IHF.Hash(tmp, nil)

	return rwdU, nil
}
