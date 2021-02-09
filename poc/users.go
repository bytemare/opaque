package poc

import (
	"github.com/bytemare/opaque"
)

var Users = map[string]*UserRecord{}

type UserRecord struct {
	HumanUserID           []byte `json:"uname"` // Human-memorizable, modifiable user identifier
	UUID                  []byte `json:"uuid"`  // Unique long-term user identifier
	ServerAkeID           []byte `json:"aid"`
	opaque.CredentialFile `json:"file"`
	opaque.Parameters     `json:"params"`
}

func NewUserRecord(username, uuid, akeID []byte, file *opaque.CredentialFile, p *opaque.Parameters) *UserRecord {
	return &UserRecord{
		HumanUserID:    username,
		UUID:           uuid,
		ServerAkeID:    akeID,
		CredentialFile: *file,
		Parameters:     *p,
	}
}

func (u *UserRecord) Server() *opaque.Server {
	return u.Parameters.Server()
}
