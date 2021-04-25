package opaque

import (
	"fmt"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/ake"
	"github.com/bytemare/opaque/core"
	"github.com/bytemare/opaque/core/envelope"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/parameters"
	"github.com/bytemare/opaque/message"
)

type Client struct {
	Core *core.Core
	Ake  *ake.Client
	Ke1  *message.KE1
	*parameters.Parameters
	mode envelope.Mode
}

func NewClient(p *Parameters) *Client {
	ip := &parameters.Parameters{
		OprfCiphersuite: p.OprfCiphersuite,
		KDF:             &internal.KDF{H: p.KDF.Get()},
		MAC:             &internal.Mac{Hash: p.MAC.Get()},
		Hash:            &internal.Hash{H: p.Hash.Get()},
		MHF:             &internal.MHF{MHF: p.MHF.Get()},
		AKEGroup:        p.AKEGroup,
		NonceLen:        p.NonceLen,
		Deserializer: p.MessageDeserializer(),
	}

	return &Client{
		Core:         core.NewCore(ip),
		Ake:          ake.NewClient(ip),
		Parameters: ip,
		mode: p.Mode,
	}
}

func (c *Client) KeyGen() (sk, pk []byte) {
	return ake.KeyGen(c.Ake.AKEGroup)
}

func (c *Client) RegistrationStart(password []byte) *message.RegistrationRequest {
	m := c.Core.OprfStart(password)
	return &message.RegistrationRequest{Data: internal.PadPoint(m, c.Parameters.OprfCiphersuite.Group())}
}

func (c *Client) RegistrationFinalize(skc []byte, creds *envelope.Credentials, resp *message.RegistrationResponse) (*message.RegistrationUpload, []byte, error) {
	envU, pkc, maskingKey, exportKey, err := c.Core.BuildEnvelope(c.mode, resp.Data, resp.Pks, skc, creds)
	if err != nil {
		return nil, nil, err
	}

	return &message.RegistrationUpload{
		PublicKey:  pkc,
		MaskingKey: maskingKey,
		Envelope:   envU.Serialize(),
	}, exportKey, nil
}

func (c *Client) AuthenticationStart(password, clientInfo []byte) *message.KE1 {
	m := c.Core.OprfStart(password)
	credReq := &message.CredentialRequest{Data: internal.PadPoint(m, c.Parameters.OprfCiphersuite.Group())}
	c.Ke1 = c.Ake.Start(clientInfo)
	c.Ke1.CredentialRequest = credReq

	return c.Ke1
}

func (c *Client) unmask(maskingNonce, maskingKey, maskedResponse []byte) ([]byte, *envelope.Envelope, error){
	crPad := c.Core.KDF.Expand(maskingKey, utils.Concatenate(0, maskingNonce, []byte(internal.TagCredentialResponsePad)), internal.PointLength(c.AkeGroup)+envelope.Size(c.mode, c.NonceLen, c.Core.MAC.Size(), c.AkeGroup))
	clear := internal.Xor(crPad, maskedResponse)

	pks := clear[:internal.PointLength(c.AkeGroup)]
	e := clear[internal.PointLength(c.AkeGroup):]

	env, _, err := envelope.DeserializeEnvelope(e, c.mode, c.NonceLen, c.Core.MAC.Size(), internal.ScalarLength(c.AkeGroup))
	if err != nil {
		return nil, nil, err
	}

	return pks, env, nil
}

func (c *Client) AuthenticationFinalize(idc, ids []byte, ke2 *message.KE2) (*message.KE3, []byte, error) {
	unblinded, err := c.Core.OprfFinalize(ke2.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	randomizedPwd := envelope.BuildPRK(c.Parameters, unblinded)
	maskingKey := c.Core.KDF.Expand(randomizedPwd, []byte(internal.TagMaskingKey), c.Core.Hash.Size())

	pks, env, err := c.unmask(ke2.MaskingNonce, maskingKey, ke2.MaskedResponse)
	if err != nil {
		return nil, nil, err
	}

	skc, pkc, exportKey, err := c.Core.RecoverSecret(c.mode, idc, ids, pks, randomizedPwd, env)
	if err != nil {
		return nil, nil, err
	}

	creds := &envelope.Credentials{
		Idc: idc,
		Ids: ids,
	}

	if creds.Idc == nil {
		creds.Idc = pkc
	}

	if creds.Ids == nil {
		creds.Ids = pks
	}

	// id, sk, peerID, peerPK - (creds, peerPK)
	ke3, _, err := c.Ake.Finalize(creds.Idc, skc, creds.Ids, pks, c.Ke1, ke2)
	if err != nil {
		return nil, nil, err
	}

	return ke3, exportKey, nil
}

func (c *Client) SessionKey() []byte {
	return c.Ake.SessionKey()
}
