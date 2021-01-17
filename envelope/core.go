package envelope

import (
	"crypto/hmac"

	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/internal"

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

type SecretCredentials struct {
	Sku []byte
}

type Core struct {
	Hash *hash.Hash
	Mode
	Mhf *mhf.Parameters
	keys
}

type keys struct {
	pad, authKey, exportKey []byte
}

func NewCore(h hash.Identifier, mode Mode, m *mhf.Parameters) *Core {
	return &Core{
		Hash: h.Get(),
		Mode: mode,
		Mhf:  m,
		keys: keys{},
	}
}

func (c *Core) buildRwdu(unblinded []byte) []byte {
	hardened := c.Mhf.Hash(unblinded, nil)
	return c.Hash.HKDFExtract(hardened, []byte(rwduSalt))
}

func (c *Core) buildKeys(rwdu, nonce []byte, padLength int) {
	c.pad = c.Hash.HKDFExpand(rwdu, append(nonce, []byte(tagPad)...), padLength)
	c.authKey = c.Hash.HKDFExpand(rwdu, append(nonce, []byte(tagAuthKey)...), c.Hash.OutputSize())
	c.exportKey = c.Hash.HKDFExpand(rwdu, append(nonce, []byte(tagExportKey)...), c.Hash.OutputSize())
}

func (c *Core) BuildEnvelope(unblinded, pks []byte, creds *Credentials, enc encoding.Encoding) (*Envelope, []byte, error) {
	rwdu := c.buildRwdu(unblinded)

	sec := SecretCredentials{Sku: creds.Sk}
	pt := sec.Sku
	nonce := utils.RandomBytes(nonceLen)

	c.buildKeys(rwdu, nonce, len(pt))

	encryptedCreds := xor(pt, c.pad)

	contents := InnerEnvelope{
		Mode:           c.Mode,
		Nonce:          nonce,
		EncryptedCreds: encryptedCreds,
	}

	encodedContents, err := encoding.JSON.Encode(contents)
	if err != nil {
		panic(err)
	}

	clearCreds, err := EncodeClearTextCredentials(creds.Idu, creds.Ids, pks, c.Mode, enc)
	if err != nil {
		return nil, nil, err
	}

	tag := c.Hash.Hmac(append(encodedContents, clearCreds...), c.authKey)
	envU := &Envelope{
		Contents: contents,
		AuthTag:  tag,
	}

	return envU, c.exportKey, nil
}

func (c *Core) RecoverSecret(idu, ids, pks, unblinded []byte, envU *Envelope, enc encoding.Encoding) (*SecretCredentials, []byte, error) {
	rwdu := c.buildRwdu(unblinded)

	contents := envU.Contents

	c.buildKeys(rwdu, contents.Nonce, len(contents.EncryptedCreds))

	encodedContents, err := encoding.JSON.Encode(contents)
	if err != nil {
		panic(err)
	}

	clearCreds, err := EncodeClearTextCredentials(idu, ids, pks, contents.Mode, enc)
	if err != nil {
		return nil, nil, err
	}

	expectedTag := c.Hash.Hmac(append(encodedContents, clearCreds...), c.authKey)

	if !hmac.Equal(expectedTag, envU.AuthTag) {
		return nil, nil, internal.ErrEnvelopeInvalidTag
	}

	pt := xor(contents.EncryptedCreds, c.pad)

	return &SecretCredentials{Sku: pt}, c.exportKey, nil
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
