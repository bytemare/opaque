package client

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/signature"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

const (
	opaqueInfo = "OPAQUE01"
)

type Client struct {
	Oprf *voprf.Client
	Ake  *ake.Client

	Group group.Group
	Hash  *hash.Hash
	Mhf   *mhf.Parameters

	nonceLen int

	meta *internal.Metadata

	keys
}

type keys struct {
	sku                     []byte
	pad, authKey, exportKey []byte
}

func New(ciphersuite voprf.Ciphersuite, h hash.Identifier, m *mhf.Parameters, k ake.Identifier) *Client {
	oprf, err := ciphersuite.Client(nil)
	if err != nil {
		panic(err)
	}

	g := ciphersuite.Group().Get(nil)
	hid := h.Get()

	return &Client{
		Oprf:     oprf,
		Ake:      k.Client(g, hid),
		Group:    g,
		Hash:     hid,
		Mhf:      m,
		nonceLen: 32,
		meta:     &internal.Metadata{},
		keys:     keys{},
	}
}

func (c *Client) OprfStart(password []byte) (blinded, blind []byte) {
	m := c.Oprf.Blind(password)
	return m, c.Oprf.Export().Blind[0]
}

func (c *Client) oprfFinish(evaluation []byte, enc encoding.Encoding) ([]byte, error) {
	ev, err := voprf.DecodeEvaluation(evaluation, enc)
	if err != nil {
		return nil, fmt.Errorf("decoding evaluation : %w", err)
	}

	n, err := c.Oprf.Finalize(ev, []byte(opaqueInfo))
	if err != nil {
		return nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	return n, nil
}

func (c *Client) initMetadata(creq *message.CredentialRequest, info1 []byte, enc encoding.Encoding) error {
	encCreq, err := enc.Encode(creq)
	if err != nil {
		return err
	}

	c.meta.CredReq = encCreq
	c.meta.Info1 = info1

	return nil
}

func (c *Client) fillMetaData(creds message.Credentials, resp *message.ServerResponse, sku []byte, enc encoding.Encoding) {
	var pku []byte

	if c.Ake.Identifier() == ake.SigmaI {
		sig := signature.Ed25519.New()
		sig.SetPrivateKey(sku)

		pku = sig.GetPublicKey()
	} else {
		sk, err := c.Group.NewScalar().Decode(sku)
		if err != nil {
			panic(err)
		}

		pku = c.Group.Base().Mult(sk).Bytes()
	}

	if err := c.meta.Fill(creds, &resp.Cresp, pku, enc); err != nil {
		panic(err)
	}
}
