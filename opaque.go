package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/cryptotools/utils"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/core/envelope"
	"github.com/bytemare/opaque/internal/encode"

	"github.com/bytemare/cryptotools/group/ciphersuite"

	"github.com/bytemare/opaque/message"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/voprf"
)

// Mode designates OPAQUE's envelope mode.
type Mode byte

const (
	// Internal designates the internal mode.
	Internal Mode = iota + 1

	// External designates the external mode.
	External
)

// CredentialIdentifier designates the server's internal unique identifier of the user entry.
type CredentialIdentifier []byte

// Parameters is the structure holding the OPAQUE configuration.
type Parameters struct {
	OprfCiphersuite voprf.Ciphersuite      `json:"oprf"`
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
		OprfCiphersuite: p.OprfCiphersuite,
		KDF:             &internal.KDF{H: p.KDF.Get()},
		MAC:             &internal.Mac{Hash: p.MAC.Get()},
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
		p.OprfCiphersuite, p.KDF, p.MAC, p.Hash, p.MHF, p.Mode, p.AKEGroup, p.NonceLen)
}

var errInvalidLength = errors.New("invalid length")

// DeserializeParameters decodes the input and returns a Parameter structure. This assumes that the encoded parameters
// are valid, and will not be checked.
func DeserializeParameters(encoded []byte) (*Parameters, error) {
	if len(encoded) != 8 {
		return nil, errInvalidLength
	}

	return &Parameters{
		OprfCiphersuite: voprf.Ciphersuite(encoded[0]),
		KDF:             hash.Hashing(encoded[1]),
		MAC:             hash.Hashing(encoded[2]),
		Hash:            hash.Hashing(encoded[3]),
		MHF:             mhf.Identifier(encoded[4]),
		Mode:            Mode(encoded[5]),
		AKEGroup:        ciphersuite.Identifier(6),
		NonceLen:        encoding.OS2IP(encoded[7:]),
	}, nil
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
		encode.EncodeVector(c.CredentialIdentifier), encode.EncodeVector(c.ClientIdentity), c.RegistrationUpload.Serialize())
}

// DeserializeClientRecord decodes the input ClientRecord given the application parameters.
func DeserializeClientRecord(encoded []byte, p *internal.Parameters) (*ClientRecord, error) {
	ci, offset1, err := encode.DecodeVector(encoded)
	if err != nil {
		return nil, fmt.Errorf("decoding credential identifier: %w", err)
	}

	idc, offset2, err := encode.DecodeVector(encoded[offset1:])
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
