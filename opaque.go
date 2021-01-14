package opaque

import (
	"fmt"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

type Parameters struct {
	Ciphersuite voprf.Ciphersuite `json:"s"`
	Hash        hash.Identifier   `json:"h"`
	AKE         ake.Identifier    `json:"a"`
	Encoding    encoding.Encoding `json:"e"`
	MHF         *mhf.Parameters   `json:"m"`
}

func (p *Parameters) Encode(enc encoding.Encoding) []byte {
	e, err := enc.Encode(p)
	if err != nil {
		panic(err)
	}

	return e
}

func (p *Parameters) Client() *Client {
	return NewClient(p.Ciphersuite, p.Hash, p.MHF, p.AKE)
}

func (p *Parameters) Server(oprfKey, akeSecretKey, akePubKey []byte) *Server {
	return NewServer(p.Ciphersuite, p.Hash, p.AKE, oprfKey, akeSecretKey, akePubKey)
}

func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s", p.Ciphersuite, p.Hash, p.AKE, p.Encoding, p.MHF)
}

func DecodeParameters(encoded []byte, enc encoding.Encoding) (*Parameters, error) {
	d, err := enc.Decode(encoded, &Parameters{})
	if err != nil {
		return nil, err
	}

	p, ok := d.(*Parameters)
	if !ok {
		return nil, internal.ErrAssertParameters
	}

	return p, nil
}
