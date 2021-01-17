package opaque

import (
	"github.com/bytemare/opaque/envelope"
)

var Users = map[string]*UserRecord{}

type Credentials struct {
	UUID          []byte `json:"uuid"` // Unique long-term user identifier
	UserPublicKey []byte `json:"pku"`
	ServerID      []byte `json:"ids"`
}

type UserRecord struct {
	HumanUserID []byte `json:"uname"` // Human-memorizable, modifiable user identifier
	Credentials
	EnvelopeMode byte   `json:"mode"`
	Envelope     []byte `json:"env"`
	OprfSecret   []byte `json:"oprfSecret"`
	ServerAkeID  []byte `json:"aid"`
	Parameters   `json:"params"`
}

func NewUserRecord(username, uuid, pku, envU, ids, oprfSecret, akeID []byte, p *Parameters, mode envelope.Mode) *UserRecord {
	return &UserRecord{
		HumanUserID: username,
		Credentials: Credentials{
			UUID:          uuid,
			UserPublicKey: pku,
			ServerID:      ids,
		},
		EnvelopeMode: byte(mode),
		Envelope:     envU,
		OprfSecret:   oprfSecret,
		ServerAkeID:  akeID,
		Parameters:   *p,
	}
}

func (u *UserRecord) Server() *Server {
	a := AkeRecords[string(u.ServerAkeID)]
	return NewServer(u.Ciphersuite, u.Hash, u.AKE, u.OprfSecret, a.SecretKey, a.PublicKey)
}
