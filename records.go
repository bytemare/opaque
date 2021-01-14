package opaque

import (
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake"
)

var AkeRecords = map[string]*AkeRecord{}

type AkeRecord struct {
	ID        []byte                 `json:"id"`
	Ake       ake.Identifier         `json:"ake"`
	Group     ciphersuite.Identifier `json:"group"`
	Hash      hash.Identifier        `json:"hash"`
	SecretKey []byte                 `json:"sk"`
	PublicKey []byte                 `json:"pk"`
}
