package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/message"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/voprf"
)

type Mode byte

const (
	Internal Mode = iota + 1
	External
)

type CredentialIdentifier []byte

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite      `json:"oprf"`
	KDF             hash.Hashing           `json:"kdf"`
	MAC             hash.Hashing           `json:"mac"`
	Hash            hash.Hashing           `json:"hash"`
	MHF             mhf.Identifier         `json:"mhf"`
	Mode            Mode          `json:"mode"`
	AKEGroup        ciphersuite.Identifier `json:"group"`
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
		[]byte{byte(p.AKEGroup)},
		encoding.I2OSP(p.NonceLen, 1))
}

func (p *Parameters) Client() *Client {
	return NewClient(p)
}

func (p *Parameters) Server() *Server {
	return NewServer(p)
}

func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s-%v-%s-%d",
		p.OprfCiphersuite, p.KDF, p.MAC, p.Hash, p.MHF, p.Mode, p.AKEGroup, p.NonceLen)
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
		Mode:            Mode(encoded[5]),
		AKEGroup:        ciphersuite.Identifier(6),
		NonceLen:        encoding.OS2IP(encoded[7:]),
	}, nil
}

type ClientRecord struct {
	CredentialIdentifier
	ClientIdentifier []byte
	*message.RegistrationUpload
}
