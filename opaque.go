package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/opaque/core/envelope"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/voprf"
)

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite `json:"s"`
	Mode            envelope.Mode     `json:"m"`
	Hash            hash.Hashing      `json:"h"`
	NonceLen        int               `json:"l"`
}

func (p *Parameters) Serialize() []byte {
	return utils.Concatenate(0, []byte{byte(p.OprfCiphersuite)}, []byte{byte(p.Mode)}, []byte{byte(p.Hash)}, encoding.I2OSP(p.NonceLen, 1))
}

func (p *Parameters) Client(m *mhf.Parameters) *Client {
	return NewClient(p.OprfCiphersuite, p.Hash, p.Mode, m)
}

func (p *Parameters) Server() *Server {
	return NewServer(p.OprfCiphersuite, p.Hash)
}

func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s", p.OprfCiphersuite, p.Hash)
}

func DeserializeParameters(encoded []byte) (*Parameters, error) {
	if len(encoded) != 4 {
		return nil, errors.New("invalid length")
	}

	return &Parameters{
		OprfCiphersuite: voprf.Ciphersuite(encoded[0]),
		Mode:            envelope.Mode(encoded[1]),
		Hash:            hash.Hashing(encoded[2]),
		NonceLen:        int(encoded[3]),
	}, nil
}
