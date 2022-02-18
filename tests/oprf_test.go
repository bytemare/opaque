// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bytemare/crypto/group"

	"github.com/bytemare/opaque/internal/encoding"
	"github.com/bytemare/opaque/internal/oprf"
	"github.com/bytemare/opaque/internal/tag"
)

type oprfVector struct {
	DST       string           `json:"groupDST"`
	Hash      string           `json:"hash"`
	KeyInfo   string           `json:"keyInfo"`
	Mode      byte             `json:"mode"`
	Seed      string           `json:"seed"`
	SkSm      string           `json:"skSm"`
	SuiteID   oprf.Ciphersuite `json:"suiteID"`
	SuiteName string           `json:"suiteName"`
	Vectors   []testVector     `json:"vectors"`
}

type test struct {
	Batch             int
	Blind             [][]byte
	BlindedElement    [][]byte
	EvaluationElement [][]byte
	Input             [][]byte
	Output            [][]byte
}

type testVectors []oprfVector

type testVector struct {
	Batch             int    `json:"Batch"`
	Blind             string `json:"Blind"`
	BlindedElement    string `json:"BlindedElement"`
	EvaluationElement string `json:"EvaluationElement"`
	Input             string `json:"Input"`
	Output            string `json:"Output"`
}

func decodeBatch(nb int, in string) ([][]byte, error) {
	v := strings.Split(in, ",")
	if len(v) != nb {
		return nil, fmt.Errorf("incoherent number of values in batch %d/%d", len(v), nb)
	}

	out := make([][]byte, nb)

	for i, s := range v {
		dec, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("hex decoding errored with %q", err)
		}
		out[i] = dec
	}

	return out, nil
}

func (tv *testVector) Decode() (*test, error) {
	blind, err := decodeBatch(tv.Batch, tv.Blind)
	// blind, err := hex.DecodeString(tv.Blind)
	if err != nil {
		return nil, fmt.Errorf(" Blind decoding errored with %q", err)
	}

	blinded, err := decodeBatch(tv.Batch, tv.BlindedElement)
	// blinded, err := hex.DecodeString(tv.BlindedElement)
	if err != nil {
		return nil, fmt.Errorf(" BlindedElement decoding errored with %q", err)
	}

	evaluationElement, err := decodeBatch(tv.Batch, tv.EvaluationElement)
	if err != nil {
		return nil, fmt.Errorf(" EvaluationElement decoding errored with %q", err)
	}

	input, err := decodeBatch(tv.Batch, tv.Input)
	// input, err := hex.DecodeString(tv.Input)
	if err != nil {
		return nil, fmt.Errorf(" Input decoding errored with %q", err)
	}

	output, err := decodeBatch(tv.Batch, tv.Output)
	// output, err := hex.DecodeString(tv.Output)
	if err != nil {
		return nil, fmt.Errorf(" Output decoding errored with %q", err)
	}

	return &test{
		Batch:             tv.Batch,
		Blind:             blind,
		BlindedElement:    blinded,
		EvaluationElement: evaluationElement,
		Input:             input,
		Output:            output,
	}, nil
}

func testBlind(t *testing.T, c oprf.Ciphersuite, test *test) {
	client := c.Client()
	for i := 0; i < len(test.Input); i++ {
		s, err := c.Group().NewScalar().Decode(test.Blind[i])
		if err != nil {
			t.Fatal(fmt.Errorf("blind decoding to scalar in suite %v errored with %q", c, err))
		}

		client.SetBlind(s)
		blinded := client.Blind(test.Input[i]).Bytes()

		if !bytes.Equal(test.BlindedElement[i], blinded) {
			t.Fatal("unexpected blinded output")
		}
	}
}

func testEvaluation(t *testing.T, c oprf.Ciphersuite, privKey *group.Scalar, test *test) {
	for i := 0; i < len(test.BlindedElement); i++ {
		b, err := c.Group().NewElement().Decode(test.BlindedElement[i])
		if err != nil {
			t.Fatal(fmt.Errorf("blind decoding to element in suite %v errored with %q", c, err))
		}

		ev := c.Evaluate(privKey, b)
		if !bytes.Equal(test.EvaluationElement[i], ev.Bytes()) {
			t.Fatal("unexpected evaluation")
		}
	}
}

func testFinalization(t *testing.T, c oprf.Ciphersuite, test *test) {
	client := c.Client()
	for i := 0; i < len(test.EvaluationElement); i++ {
		ev, err := c.Group().NewElement().Decode(test.EvaluationElement[i])
		if err != nil {
			t.Fatal(fmt.Errorf("blind decoding to element in suite %v errored with %q", c, err))
		}

		s, err := c.Group().NewScalar().Decode(test.Blind[i])
		if err != nil {
			t.Fatal(fmt.Errorf("blind decoding to scalar in suite %v errored with %q", c, err))
		}

		client.SetBlind(s)
		client.Blind(test.Input[i])

		output := client.Finalize(ev)
		if !bytes.Equal(test.Output[i], output) {
			t.Fatal("unexpected output")
		}
	}
}

func getDST(prefix []byte, c oprf.Ciphersuite) []byte {
	return encoding.Concatenate(prefix, []byte(tag.OPRF), encoding.I2OSP(0x00, 1), encoding.I2OSP(int(c), 2))
}

func (v oprfVector) test(t *testing.T) {
	s, err := hex.DecodeString(v.SkSm)
	if err != nil {
		t.Fatalf("private key decoding errored with %q\nfor sksm %v\n", err, v.SkSm)
	}

	privKey, err := v.SuiteID.Group().NewScalar().Decode(s)
	if err != nil {
		t.Fatal(fmt.Errorf("private key decoding to scalar in suite %v errored with %q", v.SuiteID, err))
	}

	decSeed, err := hex.DecodeString(v.Seed)
	if err != nil {
		t.Fatalf("decoding errored with %q\nfor seed %v\n", err, v.Seed)
	}

	decKeyInfo, err := hex.DecodeString(v.KeyInfo)
	if err != nil {
		t.Fatalf("decoding errored with %q\nfor key info %v\n", err, v.KeyInfo)
	}

	sks := v.SuiteID.DeriveKey(decSeed, decKeyInfo)

	if !sks.Sub(privKey).IsZero() {
		t.Fatalf(" DeriveKeyPair did not yield the expected key %v\n", hex.EncodeToString(sks.Bytes()))
	}

	dst, err := hex.DecodeString(v.DST)
	if err != nil {
		t.Fatalf("hex decoding errored with %q", err)
	}

	dst2 := getDST([]byte(tag.OPRFPointPrefix), v.SuiteID)
	if !bytes.Equal(dst, dst2) {
		t.Fatalf("GroupDST output is not valid.\n\twant: %v\n\tgot : %v", hex.EncodeToString(dst), hex.EncodeToString(dst2))
	}

	for i, tv := range v.Vectors {
		t.Run(fmt.Sprintf("Vector %d", i), func(t *testing.T) {
			test, err := tv.Decode()
			if err != nil {
				t.Fatal(fmt.Sprintf("batches : %v Failed %v\n", tv.Batch, err))
			}

			// Test Blinding
			testBlind(t, v.SuiteID, test)

			// Server evaluating
			testEvaluation(t, v.SuiteID, privKey, test)

			// Client finalize
			testFinalization(t, v.SuiteID, test)
		})
	}
}

func TestOPRFVectors(t *testing.T) {
	if err := filepath.Walk("oprfVectors.json",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			contents, err := ioutil.ReadFile(path)
			if err != nil {
				return err
			}

			var v testVectors
			errJSON := json.Unmarshal(contents, &v)
			if errJSON != nil {
				return errJSON
			}

			for _, tv := range v {
				if tv.Mode != 0x00 {
					continue
				}

				if tv.SuiteName == "OPRF(decaf448, SHAKE-256)" {
					continue
				}

				t.Run(tv.SuiteName, tv.test)
			}
			return nil
		}); err != nil {
		t.Fatalf("error opening test vectors: %v", err)
	}
}

func TestThing(t *testing.T) {
	log.Printf("\n - %v\n - %v\n - %v\n - %v\n - %v\n", 0x0d, '\r', byte('\r'), string(byte('\r')), uint('\r'))
}
