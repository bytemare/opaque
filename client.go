package opaque

import (
	"errors"
	"fmt"

	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/ake"
	"github.com/bytemare/opaque/internal/envelope"
	cred "github.com/bytemare/opaque/internal/message"
	"github.com/bytemare/opaque/message"
)

var errInvalidMaskedLength = errors.New("invalid masked response length")

// Client represents an OPAQUE Client, exposing its functions and holding its state.
type Client struct {
	Core *envelope.Core
	Ake  *ake.Client
	Ke1  *message.KE1
	*internal.Parameters
	mode envelope.Mode
}

// NewClient returns a new Client instantiation given the application Configuration.
func NewClient(p *Configuration) *Client {
	ip := p.toInternal()

	return &Client{
		Core:       envelope.New(ip),
		Ake:        ake.NewClient(),
		Parameters: ip,
		mode:       envelope.Mode(p.Mode),
	}
}

// KeyGen returns a key pair in the AKE group. It can then be used for the external mode.
func (c *Client) KeyGen() (secretKey, publicKey []byte) {
	return ake.KeyGen(c.AKEGroup)
}

// RegistrationInit returns a RegistrationRequest message blinding the given password.
func (c *Client) RegistrationInit(password []byte) *message.RegistrationRequest {
	m := c.Core.OprfStart(password)
	return &message.RegistrationRequest{Data: internal.PadPoint(m, c.Parameters.OprfCiphersuite.Group())}
}

// RegistrationFinalize returns a RegistrationUpload message given the server's RegistrationResponse and credentials. If
// the envelope mode is internal, then clientSecretKey is ignored and can be set to nil. For the external
// mode, clientSecretKey must be the client's private key for the AKE.
func (c *Client) RegistrationFinalize(clientSecretKey []byte, creds *Credentials,
	resp *message.RegistrationResponse) (upload *message.RegistrationUpload, exportKey []byte, err error) {
	creds2 := &envelope.Credentials{
		Idc:           creds.Client,
		Ids:           creds.Server,
		EnvelopeNonce: creds.TestEnvNonce,
		MaskingNonce:  creds.TestMaskNonce,
	}

	envU, clientPublicKey, maskingKey, exportKey, err := c.Core.BuildEnvelope(c.mode, resp.Data, resp.Pks, clientSecretKey, creds2)
	if err != nil {
		return nil, nil, fmt.Errorf("building envelope: %w", err)
	}

	return &message.RegistrationUpload{
		PublicKey:  clientPublicKey,
		MaskingKey: maskingKey,
		Envelope:   envU.Serialize(),
	}, exportKey, nil
}

// Init initiates the authentication process, returning a KE1 message blinding the given password.
// clientInfo is optional client information sent in clear, and only authenticated in KE3.
func (c *Client) Init(password, clientInfo []byte) *message.KE1 {
	m := c.Core.OprfStart(password)
	credReq := &cred.CredentialRequest{Data: internal.PadPoint(m, c.Parameters.OprfCiphersuite.Group())}
	c.Ke1 = c.Ake.Start(c.Parameters.AKEGroup, clientInfo)
	c.Ke1.CredentialRequest = credReq

	return c.Ke1
}

func (c *Client) unmask(maskingNonce, maskingKey, maskedResponse []byte) ([]byte, *envelope.Envelope, error) {
	envSize := envelope.Size(c.mode, c.NonceLen, c.Core.MAC.Size(), c.AKEGroup)
	if len(maskedResponse) != internal.PointLength[c.AKEGroup]+envSize {
		return nil, nil, errInvalidMaskedLength
	}

	crPad := c.Core.KDF.Expand(maskingKey,
		internal.Concat(maskingNonce, internal.TagCredentialResponsePad),
		internal.PointLength[c.AKEGroup]+envSize)
	clear := internal.Xor(crPad, maskedResponse)

	serverPublicKey := clear[:internal.PointLength[c.AKEGroup]]
	e := clear[internal.PointLength[c.AKEGroup]:]

	env, _, err := envelope.DeserializeEnvelope(e, c.mode, c.NonceLen, c.Core.MAC.Size(), internal.ScalarLength[c.AKEGroup])
	if err != nil {
		return nil, nil, fmt.Errorf("deserializing envelope: %w", err)
	}

	return serverPublicKey, env, nil
}

// Finish returns a KE3 message given the server's KE2 response message and the identities. If the idc
// or ids parameters are nil, the client and server's public keys are taken as identities for both.
func (c *Client) Finish(idc, ids []byte, ke2 *message.KE2) (ke3 *message.KE3, exportKey []byte, err error) {
	unblinded, err := c.Core.OprfFinalize(ke2.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := envelope.BuildPRK(c.Parameters, unblinded)
	maskingKey := c.Core.KDF.Expand(randomizedPwd, []byte(internal.TagMaskingKey), c.Core.Hash.Size())

	serverPublicKey, env, err := c.unmask(ke2.MaskingNonce, maskingKey, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("unmasking response: %w", err)
	}

	m := &envelope.Mailer{Parameters: c.Parameters}

	clientSecretKey, clientPublicKey, exportKey, err := m.RecoverEnvelope(c.mode, randomizedPwd, serverPublicKey, idc, ids, env)
	if err != nil {
		return nil, nil, fmt.Errorf("recover secret: %w", err)
	}

	if idc == nil {
		idc = clientPublicKey
	}

	if ids == nil {
		ids = serverPublicKey
	}

	// Force idu/ids to pubkeys if one is not defined
	//
	// if idc == nil || ids == nil {
	// 	idc = upload.PublicKey
	//
	// 	if serverPublicKey == nil {panic(nil)}
	//
	// 	ids = serverPublicKey
	// }

	ke3, _, err = c.Ake.Finalize(c.Parameters, idc, clientSecretKey, ids, serverPublicKey, c.Ke1, ke2)
	if err != nil {
		return nil, nil, fmt.Errorf(" AKE finalization: %w", err)
	}

	return ke3, exportKey, nil
}

// SessionKey returns the session key if the previous call to Finish() was successful.
func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
