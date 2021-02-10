package ake

import (
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/message"
)

type Metadata struct {
	CredentialRequest, CredentialResponse []byte
	IDu, IDs, ClientInfo                  []byte
}

func (m *Metadata) Init(creq *message.CredentialRequest, clientInfo []byte) {
	m.CredentialRequest = creq.Serialize()
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

	m.CredentialResponse = cresp.Serialize()
}
