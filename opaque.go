// Package opaque implements the OPAQUE PAKE protocol.
package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/voprf"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/core/envelope"
	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/message"
)

// Mode designates OPAQUE's envelope mode.
type Mode byte

const (
	// Internal designates the internal mode.
	Internal Mode = iota + 1

	// External designates the external mode.
	External
)

// Ciphersuite identifies the OPRF compatible cipher suite to be used.
type Ciphersuite voprf.Ciphersuite

const (
	// RistrettoSha512 is the OPRF cipher suite of the Ristretto255 group and SHA-512.
	RistrettoSha512 = Ciphersuite(voprf.RistrettoSha512)

	// P256Sha256 is the OPRF cipher suite of the NIST P-256 group and SHA-256.
	P256Sha256 = Ciphersuite(voprf.P256Sha256)

	// P384Sha512 is the OPRF cipher suite of the NIST P-384 group and SHA-512.
	P384Sha512 = Ciphersuite(voprf.P384Sha512)

	// P521Sha512 is the OPRF cipher suite of the NIST P-512 group and SHA-512.
	P521Sha512 = Ciphersuite(voprf.P521Sha512)
)

// CredentialIdentifier designates the server's internal unique identifier of the user entry.
type CredentialIdentifier []byte

// Parameters represents an OPAQUE configuration.
type Parameters struct {
	OprfCiphersuite Ciphersuite            `json:"oprf"`
	KDF             hash.Hashing           `json:"kdf"`
	MAC             hash.Hashing           `json:"mac"`
	Hash            hash.Hashing           `json:"hash"`
	MHF             mhf.Identifier         `json:"mhf"`
	Mode            Mode                   `json:"mode"`
	AKEGroup        ciphersuite.Identifier `json:"group"`
	NonceLen        int                    `json:"nn"`
}

func (p *Parameters) toInternal() *internal.Parameters {
	ip := &internal.Parameters{
		OprfCiphersuite: voprf.Ciphersuite(p.OprfCiphersuite),
		KDF:             &internal.KDF{H: p.KDF.Get()},
		MAC:             &internal.Mac{H: p.MAC.Get()},
		Hash:            &internal.Hash{H: p.Hash.Get()},
		MHF:             &internal.MHF{MHF: p.MHF.Get()},
		AKEGroup:        p.AKEGroup,
		NonceLen:        p.NonceLen,
		EnvelopeSize:    envelope.Size(envelope.Mode(p.Mode), p.NonceLen, p.MAC.Size(), p.AKEGroup),
	}
	ip.Init()

	return ip
}

// Serialize returns the byte encoding of the Parameters structure.
func (p *Parameters) Serialize() []byte {
	b := make([]byte, 8)
	b[0] = byte(p.OprfCiphersuite)
	b[1] = byte(p.KDF)
	b[2] = byte(p.MAC)
	b[3] = byte(p.Hash)
	b[4] = byte(p.MHF)
	b[5] = byte(p.Mode)
	b[6] = byte(p.AKEGroup)
	b[7] = encoding.I2OSP(p.NonceLen, 1)[0]

	return b
}

// Client returns a newly instantiated Client from the Parameters.
func (p *Parameters) Client() *Client {
	return NewClient(p)
}

// Server returns a newly instantiated Server from the Parameters.
func (p *Parameters) Server() *Server {
	return NewServer(p)
}

// String returns a string representation of the parameter set.
func (p *Parameters) String() string {
	return fmt.Sprintf("%s-%s-%s-%s-%s-%v-%s-%d",
		voprf.Ciphersuite(p.OprfCiphersuite), p.KDF, p.MAC, p.Hash, p.MHF, p.Mode, p.AKEGroup, p.NonceLen)
}

var errInvalidLength = errors.New("invalid length")

// DeserializeParameters decodes the input and returns a Parameter structure. This assumes that the encoded parameters
// are valid, and will not be checked.
func DeserializeParameters(encoded []byte) (*Parameters, error) {
	if len(encoded) != 8 {
		return nil, errInvalidLength
	}

	return &Parameters{
		OprfCiphersuite: Ciphersuite(encoded[0]),
		KDF:             hash.Hashing(encoded[1]),
		MAC:             hash.Hashing(encoded[2]),
		Hash:            hash.Hashing(encoded[3]),
		MHF:             mhf.Identifier(encoded[4]),
		Mode:            Mode(encoded[5]),
		AKEGroup:        ciphersuite.Identifier(6),
		NonceLen:        encoding.OS2IP(encoded[7:]),
	}, nil
}

// DefaultParams returns a default configuration with strong parameters.
func DefaultParams() *Parameters {
	return &Parameters{
		OprfCiphersuite: RistrettoSha512,
		KDF:             hash.SHA512,
		MAC:             hash.SHA512,
		Hash:            hash.SHA512,
		MHF:             mhf.Scrypt,
		Mode:            Internal,
		AKEGroup:        ciphersuite.Ristretto255Sha512,
		NonceLen:        32,
	}
}

// ClientRecord is a server-side structure enabling the storage of user relevant information.
type ClientRecord struct {
	CredentialIdentifier
	ClientIdentity []byte
	*message.RegistrationUpload
}

// Serialize returns the byte encoding of the ClientRecord.
func (c *ClientRecord) Serialize() []byte {
	return utils.Concatenate(0,
		encoding.EncodeVector(c.CredentialIdentifier), encoding.EncodeVector(c.ClientIdentity), c.RegistrationUpload.Serialize())
}

// DeserializeClientRecord decodes the input ClientRecord given the application parameters.
func DeserializeClientRecord(encoded []byte, p *internal.Parameters) (*ClientRecord, error) {
	ci, offset1, err := encoding.DecodeVector(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding credential identifier: %w", err)
	}

	idc, offset2, err := encoding.DecodeVector(encoded[offset1:])
	if err != nil {
		return nil, fmt.Errorf("decoding client identifier: %w", err)
	}

	p.Init()

	upload, err := p.DeserializeRegistrationUpload(encoded[offset1+offset2:])
	if err != nil {
		return nil, fmt.Errorf("decoding client upload: %w", err)
	}

	return &ClientRecord{
		CredentialIdentifier: ci,
		ClientIdentity:       idc,
		RegistrationUpload:   upload,
	}, nil
}
