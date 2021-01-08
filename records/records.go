package records

import (
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/voprf"
)

var OprfRecords = map[string]*OprfRecord{}

type OprfRecord struct {
	ID []byte `json:"id"`
	Ciphersuite voprf.Ciphersuite  `json:"suite"`
	OprfKey []byte `json:"k"`
}

var AkeRecords = map[string]*AkeRecord{}

type AkeRecord struct {
	ID        []byte                 `json:"id"`
	Ake       ake.Identifier         `json:"ake"`
	Group     ciphersuite.Identifier `json:"group"`
	Hash	  hash.Identifier 		 `json:"hash"`
	SecretKey []byte                 `json:"sk"`
	PublicKey []byte                 `json:"pk"`
}
