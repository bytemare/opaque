package records

var Users = map[string]*UserRecord{}

type UserRecord struct {
	HumanUserID	[]byte `json:"uname"`
	UUID []byte `json:"uuid"`
	UserPublicKey []byte `json:"pku"`
	EnvelopeMode bool `json:"mode"`
	Envelope []byte `json:"env"`
	ServerOprfID []byte `json:"oid"`
	ServerAkeID []byte `json:"aid"`
}


