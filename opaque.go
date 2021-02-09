package opaque

import (
	"fmt"

	"github.com/bytemare/opaque/core/envelope"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite `json:"s"`
	Mode            envelope.Mode     `json:"m"`
	Hash            hash.Identifier   `json:"h"`
	AKE             ake.Identifier    `json:"a"`
	NonceLen        int               `json:"l"`
}

func (p *Parameters) Encode(enc encoding.Encoding) []byte {
	e, err := enc.Encode(p)
	if err != nil {
		panic(err)
	}

	return e
}

func (p *Parameters) Client(m *mhf.Parameters) *Client {
	return NewClient(p.OprfCiphersuite, p.Hash, p.Mode, m, p.AKE, p.NonceLen)
}

func (p *Parameters) Server() *Server {
	return NewServer(p.OprfCiphersuite, p.Hash, p.AKE, p.NonceLen)
}

func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s", p.OprfCiphersuite, p.Hash, p.AKE)
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

type AkeRecord struct {
	ServerID  []byte `json:"ids"`
	SecretKey []byte `json:"sks"`
	PublicKey []byte `json:"pks"`
}

type UserRecord struct {
	HumanUserID    []byte `json:"uname"` // Human-memorizable, modifiable user identifier
	UUID           []byte `json:"uuid"`  // Unique long-term user identifier
	ServerAkeID    []byte `json:"aid"`
	CredentialFile `json:"file"`
	Parameters     `json:"params"`
}
