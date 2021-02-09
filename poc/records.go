package poc

var AkeRecords = map[string]*AkeRecord{}

type AkeRecord struct {
	ServerID  []byte `json:"ids"`
	SecretKey []byte `json:"sks"`
	PublicKey []byte `json:"pks"`
}
