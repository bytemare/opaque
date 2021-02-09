package ake

import (
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"
)

const AesGcmKeyLength = 32

type Metadata struct {
	CredReq, CredResp    []byte
	IDu, IDs, ClientInfo []byte
	KeyLen               int
}

func (m *Metadata) Init(creq *message.CredentialRequest, clientInfo []byte) {
	m.CredReq = creq.Serialize()
	m.ClientInfo = clientInfo
}

func (m *Metadata) Fill(mode envelope.Mode, cresp *message.CredentialResponse, pku, pks []byte, creds *envelope.Credentials) {
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

	m.CredResp = cresp.Serialize()
	m.KeyLen = AesGcmKeyLength
}
