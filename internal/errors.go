package internal

import "errors"

var (
	ErrParamServerPubKey    = errors.New("server public key in creds and ake are different")
	ErrParamServerNilPubKey = errors.New("no server public key")

	ErrEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")

	ErrAssertKe1        = errors.New("could not assert to Ke1")
	ErrAssertKe2        = errors.New("could not assert to Ke2")
	ErrAssertKe3        = errors.New("could not assert to Ke3")
	ErrAssertParameters = errors.New("could not assert Parameters")

	ErrAkeInvalidServerMac = errors.New("invalid server mac")
	ErrAkeInvalidClientMac = errors.New("invalid client mac")
)
