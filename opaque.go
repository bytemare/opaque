package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/group"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/voprf"
)

type CredentialIdentifier []byte

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite      `json:"oprf"`
	KDF             hash.Hashing           `json:"kdf"`
	MAC             hash.Hashing           `json:"mac"`
	Hash            hash.Hashing           `json:"hash"`
	MHF             mhf.Identifier         `json:"mhf"`
	Mode            envelope.Mode          `json:"mode"`
	Group           ciphersuite.Identifier `json:"group"`
	NonceLen        int                    `json:"nn"`
}

func (p *Parameters) Serialize() []byte {
	return utils.Concatenate(0,
		[]byte{byte(p.OprfCiphersuite)},
		[]byte{byte(p.KDF)},
		[]byte{byte(p.MAC)},
		[]byte{byte(p.Hash)},
		[]byte{byte(p.MHF)},
		[]byte{byte(p.Mode)},
		[]byte{byte(p.Group)},
		encoding.I2OSP(p.NonceLen, 1))
}

func (p *Parameters) Client() *Client {
	return NewClient(p)
}

func (p *Parameters) Server() *Server {
	return NewServer(p)
}

func (p *Parameters) MessageDeserializer() *message.Deserializer {
	return &message.Deserializer{
		Mode:            p.Mode,
		OPRFPointLength: p.OprfCiphersuite.Group(),
		AkeGroup:        p.Group,
		HashLen:         p.Hash.OutputSize(),
		MacLen:          p.MAC.OutputSize(),
		NonceLen:        p.NonceLen,
	}
}

func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s-%v-%s-%d",
		p.OprfCiphersuite, p.KDF, p.MAC, p.Hash, p.MHF, p.Mode, p.Group, p.NonceLen)
}

func DeserializeParameters(encoded []byte) (*Parameters, error) {
	if len(encoded) != 8 {
		return nil, errors.New("invalid length")
	}

	return &Parameters{
		OprfCiphersuite: voprf.Ciphersuite(encoded[0]),
		KDF:             hash.Hashing(encoded[1]),
		MAC:             hash.Hashing(encoded[2]),
		Hash:            hash.Hashing(encoded[3]),
		MHF:             mhf.Identifier(encoded[4]),
		Mode:            envelope.Mode(encoded[5]),
		Group:           ciphersuite.Identifier(6),
		NonceLen:        encoding.OS2IP(encoded[7:]),
	}, nil
}

const h2sDST = "Opaque-KeyGenerationSeed"

func DeriveSecretKey(id ciphersuite.Identifier, seed []byte) group.Scalar {
	return id.Get(nil).HashToScalar(seed, []byte(h2sDST))
}

func DeriveKeyPair(id ciphersuite.Identifier, seed []byte) (group.Scalar, group.Element) {
	g := id.Get(nil)
	sk := g.HashToScalar(seed, nil)

	return sk, g.Base().Mult(sk)
}
