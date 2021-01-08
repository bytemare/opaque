package opaque

import (
	"fmt"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

const (
	opaqueInfo = "OPAQUE01"
)

type Client struct {
	oprf *voprf.Client
	ake *ake.Client

	group group.Group
	hash *hash.Hash
	mhf mhf.PasswordKDF

	nonceLen int

	meta *internal.Metadata

	keys
}

type keys struct {
	sku []byte
	pad, authKey, exportKey []byte
}

func NewClient(ciphersuite voprf.Ciphersuite, h hash.Identifier, m mhf.Identifier, k ake.Identifier) *Client {
	
	oprf, err := ciphersuite.Client(nil)
	if err != nil {
		panic(err)
	}

	g := ciphersuite.Group().Get(nil)
	hid := h.Get()
	
	return &Client{
		oprf:     oprf,
		ake:      k.Client(g, hid),
		group:    g,
		hash:     hid,
		mhf:      m.Get(32),
		nonceLen: 32,
		meta:     &internal.Metadata{},
		keys:     keys{},
	}
}

func (c *Client) AkeKeyGen() (secretKey, publicKey []byte) {
	sk := c.group.NewScalar().Random()
	secretKey = sk.Bytes()
	publicKey = c.group.Base().Mult(sk).Bytes()
	return
}

func (c *Client) oprfStart(password []byte) (blinded, blind []byte) {
	m := c.oprf.Blind(password)
	return m, c.oprf.Export().Blind[0]
}

func (c *Client) oprfFinish(evaluation []byte, enc encoding.Encoding) ([]byte, error) {
	ev, err := voprf.DecodeEvaluation(evaluation, enc)
	if err != nil {
		return nil, fmt.Errorf("decoding evaluation : %w", err)
	}

	n, err := c.oprf.Finalize(ev, []byte(opaqueInfo))
	if err != nil {
		return nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	return n, nil
}

func (c *Client) clientMetaData(creds Credentials, resp *ServerResponse, sku []byte, enc encoding.Encoding) {
	c.meta.IDu = creds.UserID()
	if c.meta.IDu == nil {
		sk, err := c.group.NewScalar().Decode(sku)
		if err != nil {
			panic(err)
		}

		pku := c.group.Base().Mult(sk)
		c.meta.IDu = pku.Bytes()
	}

	c.meta.IDs = creds.ServerID()
	if c.meta.IDs == nil {
		c.meta.IDs = creds.ServerPublicKey()
	}

	cresp, err := enc.Encode(resp.Cresp)
	if err != nil {
		panic(err)
	}

	c.meta.CredResp = cresp
}