package message

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
)

type CredentialType byte

const (
	Sku CredentialType = 1 + iota
	Pku
	Pks
	Idu
	Ids
)

type CredentialExtension struct {
	T    CredentialType `json:"t"`
	Data []byte         `json:"d"`
}

/*
- sku must be in secret_credentials
- pku must be in either cleartext_credentials or secret_credentials
- pks and ids are recommended to be in cleartext_credentials, for servers to avoid redundancy
*/

type Credentials struct {
	CleartextCredentials []CredentialExtension `json:"c"` // require authentication but not secrecy
	SecretCredentials    []CredentialExtension `json:"s"` // require secrecy and authentication
}

func (c *CredentialExtension) Serialize(enc encoding.Encoding) ([]byte, error) {
	return enc.Encode(c)
}

func DeserializeCredentialExtension(input []byte, enc encoding.Encoding) (*[]CredentialExtension, error) {
	c, err := enc.Decode(input, &[]CredentialExtension{})
	if err != nil {
		return nil, err
	}

	ce, ok := c.(*[]CredentialExtension)
	if !ok {
		return nil, errors.New("could not assert CredentialExtension")
	}

	return ce, nil
}
