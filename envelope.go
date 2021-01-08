package opaque

import (
	"crypto/hmac"
	"errors"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
)

const (
	rwduSalt     = "rwdu"
	tagPad       = "Pad"
	tagAuthKey   = "AuthKey"
	tagExportKey = "ExportKey"

	nonceLen = 32
)

func (c *Client) buildRwdu(evaluation []byte, enc encoding.Encoding) ([]byte, error) {
	n, err := c.oprfFinish(evaluation, enc)
	if err != nil {
		return nil, err
	}

	hardened := c.mhf.Hash(n, nil)
	return c.hash.HKDFExtract(hardened, []byte(rwduSalt)), nil
}

func (c *Client) buildKeys(rwdu, nonce []byte, padLength int) {
	c.pad = c.hash.HKDFExpand(rwdu, append(nonce, []byte(tagPad)...), padLength)
	c.authKey = c.hash.HKDFExpand(rwdu, append(nonce, []byte(tagAuthKey)...), c.hash.OutputSize())
	c.exportKey = c.hash.HKDFExpand(rwdu, append(nonce, []byte(tagExportKey)...), c.hash.OutputSize())
}

func (c *Client) buildEnvelope(sku []byte, creds Credentials, resp *RegistrationResponse, enc encoding.Encoding) (*Envelope, []byte, error) {
	rwdu, err := c.buildRwdu(resp.Data, enc)
	if err != nil {
		return nil, nil, err
	}

	sec := secretCredentials{Sku: sku}
	pt := sec.Sku
	nonce := utils.RandomBytes(nonceLen)

	c.buildKeys(rwdu, nonce, len(pt))

	encryptedCreds := xor(pt, c.pad)

	clear, err := encodeClearTextCredentials(creds.Mode(), creds, enc)
	if err != nil {
		return nil, nil, err
	}

	authData := clear

	in := innerEnvelope{
		Mode:           creds.Mode(),
		Nonce:          nonce,
		EncryptedCreds: encryptedCreds,
	}

	encIn, err := encoding.JSON.Encode(in)
	if err != nil {
		panic(err)
	}

	tag := c.hash.Hmac(append(encIn, authData...), c.authKey)
	envU := &Envelope{
		Contents: in,
		AuthTag:  tag,
	}

	return envU, c.exportKey, nil
}

func (c *Client) recoverCredentials(creds Credentials, resp *ServerResponse, enc encoding.Encoding) (*secretCredentials, []byte, error) {
	rwdu, err := c.buildRwdu(resp.Cresp.Data, enc)
	if err != nil {
		return nil, nil, err
	}

	contents := resp.Cresp.Envelope.Contents

	c.buildKeys(rwdu, contents.Nonce, len(contents.EncryptedCreds))

	clear, err := encodeClearTextCredentials(contents.Mode, creds, enc)
	if err != nil {
		return nil, nil, err
	}

	authData := clear

	encodedContents, err := encoding.JSON.Encode(contents)
	if err != nil {
		panic(err)
	}
	expectedTag := c.hash.Hmac(append(encodedContents, authData...), c.authKey)

	if !hmac.Equal(expectedTag, resp.Cresp.Envelope.AuthTag) {
		return nil, nil, errors.New("tag on envelope doesn't match")
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
