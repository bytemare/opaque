package internal

import (
	"errors"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
	"github.com/bytemare/voprf"
)

type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite
	KDF             *KDF
	MAC             *Mac
	Hash            *Hash
	MHF             *MHF
	AKEGroup        ciphersuite.Identifier
	NonceLen        int
	*Deserializer
}

type Deserializer struct {
	EnvelopeSize int
	OPRFPointLength           int
	AkePointLength			  int
	AkeGroup                  ciphersuite.Identifier
	HashLen, MacLen, NonceLen int
}

func (d *Deserializer) DeserializeRegistrationRequest(input []byte) (*message.RegistrationRequest, error) {
	r := &message.RegistrationRequest{Data: input}
	if len(r.Data) != d.OPRFPointLength {
		return nil, errors.New("invalid size")
	}

	return r, nil
}

func (d *Deserializer) DeserializeRegistrationResponse(input []byte) (*message.RegistrationResponse, error) {
	if len(input) != d.OPRFPointLength+d.AkePointLength {
		return nil, errors.New("invalid size")
	}

	return &message.RegistrationResponse{
		Data: input[:d.OPRFPointLength],
		Pks:  input[d.OPRFPointLength:],
	}, nil
}

func (d *Deserializer) DeserializeRegistrationUpload(input []byte) (*message.RegistrationUpload, error) {
	l := len(input)
	if l != d.AkePointLength+d.HashLen+d.EnvelopeSize {
		return nil, errors.New("invalid input length")
	}

	pku := input[:d.AkePointLength]
	maskingKey := input[d.AkePointLength : d.AkePointLength+d.HashLen]
	env := input[d.AkePointLength+d.HashLen:]

	return &message.RegistrationUpload{
		PublicKey:  pku,
		MaskingKey: maskingKey,
		Envelope:   env,
	}, nil
}

func (d *Deserializer) DeserializeCredentialRequest(input []byte) (*message.CredentialRequest, error) {
	if len(input) != d.OPRFPointLength {
		return nil, errors.New("invalid input size")
	}

	return &message.CredentialRequest{Data: input[:d.OPRFPointLength]}, nil
}

func (d *Deserializer) deserializeCredentialResponse(input []byte) (*message.CredentialResponse, int, error) {
	if len(input) <= d.OPRFPointLength+d.NonceLen+d.AkePointLength+d.EnvelopeSize {
		return nil, 0, errors.New("invalid CredentialResponse length")
	}

	return &message.CredentialResponse{
		Data:           input[:d.OPRFPointLength],
		MaskingNonce:   input[d.OPRFPointLength : d.OPRFPointLength+d.NonceLen],
		MaskedResponse: input[d.OPRFPointLength+d.NonceLen : d.OPRFPointLength+d.NonceLen+d.AkePointLength+d.EnvelopeSize],
	}, d.OPRFPointLength + d.NonceLen + d.AkePointLength + d.EnvelopeSize, nil
}

func (d *Deserializer) DeserializeCredentialResponse(input []byte) (*message.CredentialResponse, error) {
	c, _, err := d.deserializeCredentialResponse(input)
	return c, err
}

func (d *Deserializer) DeserializeKE1(input []byte) (*message.KE1, error) {
	if len(input) != d.OPRFPointLength+d.NonceLen+2+d.AkePointLength {
		return nil, errors.New("invalid input length")
	}

	creq, err := d.DeserializeCredentialRequest(input)
	if err != nil {
		return nil, err
	}

	nonceU := input[d.OPRFPointLength : d.OPRFPointLength+d.NonceLen]

	info, offset, err := encoding.DecodeVector(input[d.OPRFPointLength+d.NonceLen:])
	if err != nil {
		return nil, err
	}

	offset = d.OPRFPointLength + d.NonceLen + offset
	epku := input[offset:]

	if len(epku) != d.AkePointLength {
		return nil, errors.New("invalid epku length")
	}

	return &message.KE1{
		CredentialRequest: creq,
		NonceU:            nonceU,
		ClientInfo:        info,
		EpkU:              epku,
	}, nil
}

func (d *Deserializer) DeserializeKE2(input []byte) (*message.KE2, error) {
	if len(input) < d.OPRFPointLength+d.NonceLen+d.AkePointLength+d.EnvelopeSize+d.NonceLen+d.AkePointLength+d.MacLen {
		return nil, errors.New("KE2 is too short")
	}

	cresp, offset, err := d.deserializeCredentialResponse(input)
	if err != nil {
		return nil, err
	}

	nonceS := input[offset : offset+d.NonceLen]
	offset += d.NonceLen
	epks := input[offset : offset+d.AkePointLength]
	offset += d.AkePointLength

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

func (d *Deserializer) DeserializeKE3(input []byte) (*message.KE3, error) {
	if len(input) != d.MacLen {
		return nil, errors.New("invalid mac length")
	}

	return &message.KE3{Mac: input}, nil
}