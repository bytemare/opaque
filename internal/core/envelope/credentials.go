package envelope

import (
	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal/encode"
)

type CleartextCredentials struct {
	Pks []byte
	Idc []byte
	Ids []byte
}

func (c *CleartextCredentials) Serialize() []byte {
	var u, s []byte
	if c.Idc != nil {
		u = encode.EncodeVector(c.Idc)
	}

	if c.Ids != nil {
		s = encode.EncodeVector(c.Ids)
	}

	return utils.Concatenate(0, c.Pks, u, s)
}

func CreateCleartextCredentials(pkc, pks []byte, credentials *Credentials) *CleartextCredentials {
	if pks == nil {
		panic("nil pks")
	}

	idc := credentials.Idc
	if idc == nil {
		if pkc == nil {
			panic("nil pkc")
		}

		idc = pkc
	}

	ids := credentials.Ids
	if ids == nil {
		ids = pks
	}

	return &CleartextCredentials{
		Pks: pks,
		Idc: idc,
		Ids: ids,
	}
}
