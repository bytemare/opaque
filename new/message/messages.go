package message

// Registration
//type Message byte
//
//const (
//	RegistrationRequest = 1 + iota
//)
//

type ClientInit struct {
	*CredentialRequest
	KE1   []byte
	Info1 []byte // optional
}

type ServerResponse struct {
	*CredentialResponse
	KE2 []byte

	Info2  []byte // optional
	EInfo2 []byte // optional
}

type ClientFinish struct {
	KE3 []byte

	Info3  []byte // optional
	EInfo3 []byte // optional
}

type RegistrationRequest struct {
	Data []byte // encoded OPRF element
}

type RegistrationResponse struct {
	Data           []byte
	Pks            []byte
	SecretTypes    []CredentialType
	CleartextTypes []CredentialType
}

type RegistrationUpload struct {
	Envelope *Envelope
	Pku      []byte
}

// Authentication
type CredentialRequest struct {
	Data []byte
}

type CredentialResponse struct {
	Data     []byte
	Envelope *Envelope
}
