package opaque

import (
	"errors"
	"fmt"
	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/opaque/core/envelope"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/voprf"
)

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite `json:"s"`
	KDF             hash.Hashing
	MAC             hash.Hashing
	Hash            hash.Hashing `json:"h"`
	MHF             mhf.Identifier
	Mode            envelope.Mode `json:"m"`
	AkeGroup        ciphersuite.Identifier
	NonceLen        int `json:"l"`
}

func (p *Parameters) Serialize() []byte {
	return utils.Concatenate(0, []byte{byte(p.OprfCiphersuite)}, []byte{byte(p.Mode)}, []byte{byte(p.Hash)}, encoding.I2OSP(p.NonceLen, 1))
}

func (p *Parameters) Client() *Client {
	return NewClient(p.OprfCiphersuite, p.KDF, p.MAC, p.Hash, p.MHF.Get(), p.Mode, p.AkeGroup)
}

func (p *Parameters) Server() *Server {
	return NewServer(p.OprfCiphersuite, p.KDF, p.MAC, p.Hash, p.AkeGroup)
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
