// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package encoding

func Concat(a, b []byte) []byte {
	e := make([]byte, 0, len(a)+len(b))
	e = append(e, a...)
	e = append(e, b...)

	return e
}

func Concat3(a, b, c []byte) []byte {
	e := make([]byte, 0, len(a)+len(b)+len(c))
	e = append(e, a...)
	e = append(e, b...)
	e = append(e, c...)

	return e
}

func SuffixString(a []byte, b string) []byte {
	e := make([]byte, 0, len(a)+len(b))
	e = append(e, a...)
	e = append(e, b...)

	return e
}

// Concatenate takes the variadic array of input and returns a concatenation of it.
func Concatenate(input ...[]byte) []byte {
	length := 0
	for _, b := range input {
		length += len(b)
	}

	buf := make([]byte, 0, length)

	for _, in := range input {
		buf = append(buf, in...)
	}

	return buf
}
