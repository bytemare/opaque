package threeDH

import (
	"errors"
	"github.com/bytemare/cryptotools/encoding"
)

type KE1 struct {
	NonceU []byte `json:"n"`
	EpkU   []byte `json:"e"`
}

func DecodeKe1(input []byte, enc encoding.Encoding) (*KE1, error) {
	d, err := enc.Decode(input, &KE1{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*KE1)
	if !ok {
		return nil, errors.New("could not assert KE1")
	}

	return de, nil
}

type KE2 struct {
	NonceS []byte `json:"n"`
	EpkS   []byte `json:"e"`
	Mac    []byte `json:"m"`
}

func DecodeKe2(input []byte, enc encoding.Encoding) (*KE2, error) {
	d, err := enc.Decode(input, &KE2{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*KE2)
	if !ok {
		return nil, errors.New("could not assert KE2")
	}

	return de, nil
}

type KE3 struct {
	Mac []byte `json:"m"`
}

func DecodeKe3(input []byte, enc encoding.Encoding) (*KE3, error) {
	d, err := enc.Decode(input, &KE3{})
	if err != nil {
		return nil, err
	}

	de, ok := d.(*KE3)
	if !ok {
		return nil, errors.New("could not assert KE3")
	}

	return de, nil
}
