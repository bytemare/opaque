package opaque

// Registration

type RegistrationRequest struct {
	Data []byte `json:"data"`
}

type RegistrationResponse struct {
	Data           []byte `json:"data"`
	Pks            []byte `json:"pks"`
}

type RegistrationUpload struct {
	Envelope Envelope `json:"env"`
	Pku      []byte   `json:"pku"`
}

// Authentication

type CredentialRequest struct {
	Data []byte `json:"data"`
}

type CredentialResponse struct {
	Data     []byte   `json:"data"`
	Pks      []byte   `json:"pks"`
	Envelope Envelope `json:"env"`
}

// Protocol Messages

type ClientInit struct {
	Creq  CredentialRequest `json:"creq"`
	KE1   []byte            `json:"ke1"`
	Info1 []byte            `json:"info1,omitempty"`
}

type ServerResponse struct {
	Cresp CredentialResponse `json:"cres"`
	KE2   []byte             `json:"ke2"`

	Info2  []byte  `json:"info2,omitempty"`
	EInfo2 []byte  `json:"einfo2,omitempty"`
}

type ClientFinish struct {
	KE3 []byte  `json:"ke3"`

	Info3  []byte  `json:"info3,omitempty"`
	EInfo3 []byte  `json:"einfo3,omitempty"`
}
