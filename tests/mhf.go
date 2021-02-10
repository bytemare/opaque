package tests

import "github.com/bytemare/cryptotools/mhf"

type MHF byte

const (
	IdentityMHF = 5
)

// Available reports whether the given kdf function is linked into the binary.
func (i MHF) Available() bool {
	return true
}

// Harden uses default parameters for the key derivation function over the input password and salt.
func (i MHF) Harden(password, _ []byte, _ int) []byte {
	return password
}

// HardenParam wraps and calls the key derivation function
func (i MHF) HardenParam(password, _ []byte, _, _, _, _ int) []byte {
	return password
}

// DefaultParameters returns a pointer to a MHF struct containing
// the standard recommended default parameters for the kdf.
func (i MHF) DefaultParameters() *mhf.Parameters {
	return nil
}

// String returns the string name of the hashing function.
func (i MHF) String() string {
	return "Identity"
}
