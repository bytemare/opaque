package internal

import "errors"

var (
	ErrEnvelopeInvalidTag = errors.New("invalid envelope authentication tag")
	ErrAssertParameters = errors.New("could not assert Parameters")

	ErrAkeInvalidServerMac = errors.New("invalid server mac")
	ErrAkeInvalidClientMac = errors.New("invalid client mac")
)
