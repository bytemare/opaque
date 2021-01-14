package client

import (
	"crypto/hmac"

	"github.com/bytemare/opaque/internal"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
)

const (
	rwduSalt     = "rwdu"
	tagPad       = "Pad"
	tagAuthKey   = "AuthKey"
	tagExportKey = "ExportKey"

	nonceLen = 32
)

type secretCredentials struct {
	Sku []byte
}

func (c *Client) buildRwdu(unblinded []byte) []byte {
	hardened := c.Mhf.Hash(unblinded, nil)
	return c.Hash.HKDFExtract(hardened, []byte(rwduSalt))
}

func (c *Client) buildKeys(rwdu, nonce []byte, padLength int) {
	c.pad = c.Hash.HKDFExpand(rwdu, append(nonce, []byte(tagPad)...), padLength)
	c.authKey = c.Hash.HKDFExpand(rwdu, append(nonce, []byte(tagAuthKey)...), c.Hash.OutputSize())
	c.exportKey = c.Hash.HKDFExpand(rwdu, append(nonce, []byte(tagExportKey)...), c.Hash.OutputSize())
}

func (c *Client) BuildEnvelope(sku []byte, creds message.Credentials, resp *message.RegistrationResponse, enc encoding.Encoding) (*envelope.Envelope, []byte, error) {
	unblinded, err := c.oprfFinish(resp.Data, enc)
	if err != nil {
		return nil, nil, err
	}

	rwdu := c.buildRwdu(unblinded)

	sec := secretCredentials{Sku: sku}
	pt := sec.Sku
	nonce := utils.RandomBytes(nonceLen)

	c.buildKeys(rwdu, nonce, len(pt))

	encryptedCreds := xor(pt, c.pad)

	clear, err := message.EncodeClearTextCredentials(creds.EnvelopeMode(), creds, enc)
	if err != nil {
		return nil, nil, err
	}

	authData := clear

	in := envelope.InnerEnvelope{
		Mode:           creds.EnvelopeMode(),
		Nonce:          nonce,
		EncryptedCreds: encryptedCreds,
	}

	encIn, err := encoding.JSON.Encode(in)
	if err != nil {
		panic(err)
	}

	tag := c.Hash.Hmac(append(encIn, authData...), c.authKey)
	envU := &envelope.Envelope{
		Contents: in,
		AuthTag:  tag,
	}

	return envU, c.exportKey, nil
}

func (c *Client) recoverCredentials(creds message.Credentials, response *message.CredentialResponse, enc encoding.Encoding) (*secretCredentials, []byte, error) {
	unblinded, err := c.oprfFinish(response.Data, enc)
	if err != nil {
		return nil, nil, err
	}

	rwdu := c.buildRwdu(unblinded)

	contents := response.Envelope.Contents

	c.buildKeys(rwdu, contents.Nonce, len(contents.EncryptedCreds))

	clear, err := message.EncodeClearTextCredentials(contents.Mode, creds, enc)
	if err != nil {
		return nil, nil, err
	}

	authData := clear

	encodedContents, err := encoding.JSON.Encode(contents)
	if err != nil {
		panic(err)
	}

	expectedTag := c.Hash.Hmac(append(encodedContents, authData...), c.authKey)

	if !hmac.Equal(expectedTag, response.Envelope.AuthTag) {
		return nil, nil, internal.ErrEnvelopeInvalidTag
	}

	pt := xor(contents.EncryptedCreds, c.pad)

	secret := pt

	return &secretCredentials{Sku: secret}, c.exportKey, nil
}

func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xoring slices must be of same length")
	}

	dst := make([]byte, len(a))

	// if the size is fixed, we could unroll the loop
	for i, r := range a {
		dst[i] = r ^ b[i]
	}

	return dst
}
