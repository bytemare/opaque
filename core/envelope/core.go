package envelope

import (
	"crypto/hmac"
	"fmt"
	"github.com/bytemare/cryptotools/group/ciphersuite"
	"github.com/bytemare/cryptotools/hash"
	"github.com/bytemare/cryptotools/mhf"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/voprf"
)

const (
	nonceLen     = 32
	opaqueInfo   = "OPAQUE"
	tagPad       = "Pad"
	tagAuthKey   = "AuthKey"
	tagExportKey = "ExportKey"
)

type Core struct {
	Group ciphersuite.Identifier
	Oprf  *voprf.Client
	Hash  *hash.Hash
	Mode
	Mhf *mhf.Parameters
	keys
}

// todo: this is for testing. Delete later.
func (c *Core) DebugGetKeys() (pad, authKey, exportKey, prk []byte) {
	return c.pad, c.authKey, c.exportKey, c.prk
}

type keys struct {
	pad, authKey, exportKey, prk []byte
}

func NewCore(suite voprf.Ciphersuite, h hash.Identifier, mode Mode, m *mhf.Parameters) *Core {
	oprf, err := suite.Client(nil)
	if err != nil {
		panic(err)
	}

	return &Core{
		Group: suite.Group(),
		Oprf:  oprf,
		Hash:  h.Get(),
		Mode:  mode,
		Mhf:   m,
		keys:  keys{},
	}
}

func (c *Core) OprfStart(password []byte) []byte {
	return c.Oprf.Blind(password)
}

func (c *Core) oprfFinish(data []byte) ([]byte, error) {
	ev := &voprf.Evaluation{Elements: [][]byte{data}}
	return c.Oprf.Finalize(ev, []byte(opaqueInfo))
}

func (c *Core) buildRwdu(unblinded, nonce []byte) []byte {
	//hardened := c.Mhf.Harden(unblinded, nil)
	hardened := unblinded
	return c.Hash.HKDFExtract(hardened, nonce)
}

func (c *Core) buildKeys(rwdu []byte, padLength int) {
	c.pad = c.Hash.HKDFExpand(rwdu, []byte(tagPad), padLength)
	c.authKey = c.Hash.HKDFExpand(rwdu, []byte(tagAuthKey), c.Hash.OutputSize())
	c.exportKey = c.Hash.HKDFExpand(rwdu, []byte(tagExportKey), c.Hash.OutputSize())
}

func (c *Core) BuildEnvelope(evaluation, pks []byte, creds *Credentials) (*Envelope, []byte, error) {
	unblinded, err := c.oprfFinish(evaluation)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	nonce := creds.Nonce //utils.RandomBytes(nonceLen)
	if nonce == nil {
		panic("nil nonce")
	}
	rwdu := c.buildRwdu(unblinded, nonce)
	c.prk = rwdu
	sec := SecretCredentials{Sku: creds.Sk}
	pt := sec.Serialize()

	c.buildKeys(rwdu, len(pt))

	encryptedCreds := internal.Xor(pt, c.pad)

	contents := InnerEnvelope{
		Mode:           c.Mode,
		Nonce:          nonce,
		EncryptedCreds: encryptedCreds,
	}

	clearCreds := EncodeClearTextCredentials(creds.Idu, creds.Ids, pks, c.Mode)

	tag := c.Hash.Hmac(append(contents.Serialize(), clearCreds...), c.authKey)
	envU := &Envelope{
		Contents: contents,
		AuthTag:  tag,
	}

	return envU, c.exportKey, nil
}

func (c *Core) RecoverSecret(idu, ids, pks, evaluation []byte, envU *Envelope) (*SecretCredentials, []byte, error) {
	unblinded, err := c.oprfFinish(evaluation)
	if err != nil {
		return nil, nil, fmt.Errorf("finalizing OPRF : %w", err)
	}

	contents := envU.Contents
	rwdu := c.buildRwdu(unblinded, contents.Nonce)
	c.buildKeys(rwdu, len(contents.EncryptedCreds))

	clearCreds := EncodeClearTextCredentials(idu, ids, pks, contents.Mode)

	expectedTag := c.Hash.Hmac(append(contents.Serialize(), clearCreds...), c.authKey)

	if !hmac.Equal(expectedTag, envU.AuthTag) {
		return nil, nil, internal.ErrEnvelopeInvalidTag
	}

	pt := internal.Xor(contents.EncryptedCreds, c.pad)
	sec, _ := DeserializeSecretCredentials(pt)

	return sec, c.exportKey, nil
}
