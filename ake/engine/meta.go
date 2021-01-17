package engine

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
)

const AesGcmKeyLength = 32

type Metadata struct {
	CredReq, CredResp []byte
	IDu, IDs, Info1   []byte
	KeyLen            int
}

func (m *Metadata) Init(creq *message.CredentialRequest, info1 []byte, enc encoding.Encoding) error {
	encCreq, err := enc.Encode(creq)
	if err != nil {
		return err
	}

	m.CredReq = encCreq
	m.Info1 = info1

	return nil
}

func (m *Metadata) Fill(mode envelope.Mode, cresp *message.CredentialResponse, pku, pks []byte, creds *envelope.Credentials, enc encoding.Encoding) error {
	if mode == envelope.CustomIdentifier {
		m.IDu = creds.Idu
		m.IDs = creds.Ids
	}

	if m.IDu == nil {
		m.IDu = pku
	}

	if m.IDs == nil {
		m.IDs = pks
	}

	encCresp, err := enc.Encode(cresp)
	if err != nil {
		panic(err)
	}

	m.CredResp = encCresp
	m.KeyLen = AesGcmKeyLength

	return nil
}
