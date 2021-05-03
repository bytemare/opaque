// Package internal provides structures and functions to operate OPAQUE that are not part of the public API.
package internal

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/voprf"

	"github.com/bytemare/opaque/internal/encoding"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var (
	errInvalidSize          = errors.New("invalid message size")
	errInvalidMessageLength = errors.New("invalid message length")
	errCredReqShort         = errors.New(" CredentialRequest too short")
	errInvalidCredRespShort = errors.New(" CredentialResponse too short")
	errInvalidEpkuLength    = errors.New("invalid epku length")
	errShortMessage         = errors.New("message is too short")
)

type Parameters struct {
	KDF             *KDF
	MAC             *Mac
	Hash            *Hash
	MHF             *MHF
	NonceLen        int
	EnvelopeSize    int
	OPRFPointLength int
	AkePointLength  int
	OprfCiphersuite voprf.Ciphersuite
	AKEGroup        ciphersuite.Identifier
}

func (p *Parameters) Init() *Parameters {
	p.OPRFPointLength = PointLength[p.OprfCiphersuite.Group()]
	p.AkePointLength = PointLength[p.AKEGroup]

	return p
}

func (p *Parameters) DeserializeRegistrationRequest(input []byte) (*message.RegistrationRequest, error) {
	r := &message.RegistrationRequest{Data: input}
	if len(r.Data) != p.OPRFPointLength {
		return nil, errInvalidSize
	}

	return r, nil
}

func (p *Parameters) DeserializeRegistrationResponse(input []byte) (*message.RegistrationResponse, error) {
	if len(input) != p.OPRFPointLength+p.AkePointLength {
		return nil, errInvalidSize
	}

	return &message.RegistrationResponse{
		Data: input[:p.OPRFPointLength],
		Pks:  input[p.OPRFPointLength:],
	}, nil
}

func (p *Parameters) DeserializeRegistrationUpload(input []byte) (*message.RegistrationUpload, error) {
	if len(input) != p.AkePointLength+p.Hash.Size()+p.EnvelopeSize {
		return nil, errInvalidMessageLength
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

func (p *Parameters) DeserializeCredentialRequest(input []byte) (*cred.CredentialRequest, int, error) {
	if len(input) <= p.OPRFPointLength {
		return nil, 0, errCredReqShort
	}

	return &cred.CredentialRequest{Data: input[:p.OPRFPointLength]}, p.OPRFPointLength, nil
}

func (p *Parameters) deserializeCredentialResponse(input []byte) (*cred.CredentialResponse, int, error) {
	supposedLength := p.OPRFPointLength + p.NonceLen + p.AkePointLength + p.EnvelopeSize
	if len(input) < supposedLength {
		return nil, 0, errInvalidCredRespShort
	}

	return &cred.CredentialResponse{
		Data:           input[:p.OPRFPointLength],
		MaskingNonce:   input[p.OPRFPointLength : p.OPRFPointLength+p.NonceLen],
		MaskedResponse: input[p.OPRFPointLength+p.NonceLen : supposedLength],
	}, supposedLength, nil
}

func (p *Parameters) DeserializeCredentialResponse(input []byte) (*cred.CredentialResponse, error) {
	c, _, err := p.deserializeCredentialResponse(input)
	return c, err
}

func (p *Parameters) DeserializeKE1(input []byte) (*message.KE1, error) {
	if len(input) < p.OPRFPointLength+p.NonceLen+2+p.AkePointLength {
		return nil, errInvalidSize
	}

	creq, offset, err := p.DeserializeCredentialRequest(input)
	if err != nil {
		return nil, fmt.Errorf("deserializing the credential crequest: %w", err)
	}

	nonceU := input[offset : offset+p.NonceLen]

	info, offset2, err := encoding.DecodeVector(input[offset+p.NonceLen:])
	if err != nil {
		return nil, fmt.Errorf("decoding the client info: %w", err)
	}

	offset = offset + p.NonceLen + offset2
	epku := input[offset:]

	if len(epku) != p.AkePointLength {
		return nil, errInvalidEpkuLength
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
		return nil, errShortMessage
	}

	cresp, offset, err := p.deserializeCredentialResponse(input)
	if err != nil {
		return nil, fmt.Errorf("decoding credential response: %w", err)
	}

	nonceS := input[offset : offset+p.NonceLen]
	offset += p.NonceLen
	epks := input[offset : offset+p.AkePointLength]
	offset += p.AkePointLength

	einfo, length, err := encoding.DecodeVector(input[offset:])
	if err != nil {
		return nil, fmt.Errorf("decoding einfo: %w", err)
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
		return nil, errInvalidMessageLength
	}

	return &message.KE3{Mac: input}, nil
}
