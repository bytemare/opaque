package internal

import "errors"

// ErrConfigurationInvalidLength happens when deserializing a configuration of invalid length.
var ErrConfigurationInvalidLength = errors.New("invalid encoded configuration length")
