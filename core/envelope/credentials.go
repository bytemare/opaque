package envelope

import (
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/internal"
)

type SecretCredentials struct {
	Skc []byte
}

func (s *SecretCredentials) Serialize() []byte {
	return s.Skc
}

func DeserializeSecretCredentials(input []byte) *SecretCredentials {
	return &SecretCredentials{input}
}

type CleartextCredentials struct {
	Pks []byte
	Idc []byte
	Ids []byte
}

func (c *CleartextCredentials) Serialize() []byte {
	var u, s []byte
	if c.Idc != nil {
		u = internal.EncodeVector(c.Idc)
	}

	if c.Ids != nil {
		s = internal.EncodeVector(c.Ids)
	}

	return utils.Concatenate(0, c.Pks, u, s)
}

func CreateCleartextCredentials(pkc, pks []byte, credentials *Credentials) *CleartextCredentials {
	var idc, ids []byte

	if pks == nil {
		panic("nil pks")
	}

	if credentials.Idc == nil {
		if pkc == nil {
			panic("nil pkc")
		}

		idc = pkc
	}

	if credentials.Ids == nil {
		//if pks == nil {
		//	panic("")
		//}

		ids = pks
	}

	return &CleartextCredentials{
		Pks: pks,
		Idc: idc,
		Ids: ids,
	}
}
