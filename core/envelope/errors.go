package envelope

import "errors"

var (
	ErrCredsInvalidMode = errors.New("credentials - invalid ClearTextCredentials mode")
	ErrCredsBaseNoIDu   = errors.New("credentials - no idu in Base mode")
	ErrCredsBaseNiIDs   = errors.New("credentials - no ids in Base mode")
)
