package message

type InnerEnvelope struct {
	Nonce    []byte `json:"n"`
	Ct       []byte `json:"c"`
	AuthData []byte `json:"a"`
}

type Envelope struct {
	Contents InnerEnvelope `json:"e"`
	AuthTag  []byte        `json:"t"`
}
