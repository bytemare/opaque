package parameters

import (
	"errors"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite
	KDF             *internal.KDF
	MAC             *internal.Mac
	Hash            *internal.Hash
	MHF             *internal.MHF
	AKEGroup        ciphersuite.Identifier
	NonceLen        int

	EnvelopeSize    int
	OPRFPointLength int
	AkePointLength  int
}

func (p *Parameters) Init() *Parameters {
	p.OPRFPointLength = internal.PointLength[p.OprfCiphersuite.Group()]
	p.AkePointLength = internal.PointLength[p.AKEGroup]

	return p
}

func (p *Parameters) DeserializeRegistrationRequest(input []byte) (*message.RegistrationRequest, error) {
	r := &message.RegistrationRequest{Data: input}
	if len(r.Data) != p.OPRFPointLength {
		return nil, errors.New("invalid size")
	}

	return r, nil
}

func (p *Parameters) DeserializeRegistrationResponse(input []byte) (*message.RegistrationResponse, error) {
	if len(input) != p.OPRFPointLength+p.AkePointLength {
		return nil, errors.New("invalid size")
	}

	return &message.RegistrationResponse{
		Data: input[:p.OPRFPointLength],
		Pks:  input[p.OPRFPointLength:],
	}, nil
}

func (p *Parameters) DeserializeRegistrationUpload(input []byte) (*message.RegistrationUpload, error) {
	l := len(input)
	if l != p.AkePointLength+p.Hash.Size()+p.EnvelopeSize {
		return nil, errors.New("invalid input length")
	}

	pku := input[:p.AkePointLength]
	maskingKey := input[p.AkePointLength : p.AkePointLength+p.Hash.Size()]
	env := input[p.AkePointLength+p.Hash.Size():]

	return &message.RegistrationUpload{
		PublicKey:  pku,
		MaskingKey: maskingKey,
		Envelope:   env,
	}, nil
}

func (p *Parameters) DeserializeCredentialRequest(input []byte) (*message.CredentialRequest, int, error) {
	if len(input) <= p.OPRFPointLength {
		return nil, 0, errors.New("CredentialRequest too short")
	}

	return &message.CredentialRequest{Data: input[:p.OPRFPointLength]}, p.OPRFPointLength, nil
}

func (p *Parameters) deserializeCredentialResponse(input []byte) (*message.CredentialResponse, int, error) {
	supposedLength := p.OPRFPointLength + p.NonceLen + p.AkePointLength + p.EnvelopeSize
	if len(input) < supposedLength {
		return nil, 0, errors.New("invalid CredentialResponse length")
	}

	return &message.CredentialResponse{
		Data:           input[:p.OPRFPointLength],
		MaskingNonce:   input[p.OPRFPointLength : p.OPRFPointLength+p.NonceLen],
		MaskedResponse: input[p.OPRFPointLength+p.NonceLen : supposedLength],
	}, supposedLength, nil
}

func (p *Parameters) DeserializeCredentialResponse(input []byte) (*message.CredentialResponse, error) {
	c, _, err := p.deserializeCredentialResponse(input)
	return c, err
}

func (p *Parameters) DeserializeKE1(input []byte) (*message.KE1, error) {
	if len(input) != p.OPRFPointLength+p.NonceLen+2+p.AkePointLength {
		return nil, errors.New("invalid input length")
	}

	creq, offset, err := p.DeserializeCredentialRequest(input)
	if err != nil {
		return nil, err
	}

	nonceU := input[offset : offset+p.NonceLen]

	info, offset2, err := encoding.DecodeVector(input[offset+p.NonceLen:])
	if err != nil {
		return nil, err
	}

	offset = offset + p.NonceLen + offset2
	epku := input[offset:]

	if len(epku) != p.AkePointLength {
		return nil, errors.New("invalid epku length")
	}

	return &message.KE1{
		CredentialRequest: creq,
		NonceU:            nonceU,
		ClientInfo:        info,
		EpkU:              epku,
	}, nil
}

func (p *Parameters) DeserializeKE2(input []byte) (*message.KE2, error) {
	if len(input) < p.OPRFPointLength+p.NonceLen+p.AkePointLength+p.EnvelopeSize+p.NonceLen+p.AkePointLength+p.MAC.Size() {
		return nil, errors.New("KE2 is too short")
	}

	cresp, offset, err := p.deserializeCredentialResponse(input)
	if err != nil {
		return nil, err
	}

	nonceS := input[offset : offset+p.NonceLen]
	offset += p.NonceLen
	epks := input[offset : offset+p.AkePointLength]
	offset += p.AkePointLength

	einfo, length, err := encoding.DecodeVector(input[offset:])
	if err != nil {
		return nil, err
	}

	mac := input[offset+length:]

	return &message.KE2{
		CredentialResponse: cresp,
		NonceS:             nonceS,
		EpkS:               epks,
		Einfo:              einfo,
		Mac:                mac,
	}, nil
}

func (p *Parameters) DeserializeKE3(input []byte) (*message.KE3, error) {
	if len(input) != p.MAC.Size() {
		return nil, errors.New("invalid mac length")
	}

	return &message.KE3{Mac: input}, nil
}
