// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/bytemare/hash"
	"github.com/bytemare/ksf"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	"github.com/bytemare/opaque/internal/oprf"
)

const fmtGotValidInput = "got %q but input is valid"

type fuzzConfError struct {
	error       error
	value       interface{}
	isAvailable bool
}

// skipErrorOnCondition skips the test if we find the expected error in err and cond if false.
func skipErrorOnCondition(t *testing.T, expected error, ce *fuzzConfError) error {
	if strings.Contains(expected.Error(), ce.error.Error()) {
		if ce.isAvailable {
			return fmt.Errorf("got %q but input is valid: %q", ce.error, ce.value)
		}
		t.Skip()
	}

	return nil
}

func fuzzTestConfigurationError(t *testing.T, c *opaque.Configuration, err error) error {
	// Errors tested for
	errorTests := []*fuzzConfError{
		{errors.New("invalid KDF id"), c.KDF, hash.Hash(c.KDF).Available()},
		{errors.New("invalid MAC id"), c.MAC, hash.Hash(c.MAC).Available()},
		{errors.New("invalid Hash id"), c.Hash, hash.Hash(c.Hash).Available()},
		{errors.New("invalid KSF id"), c.KSF.Identifier, c.KSF.Identifier == 0 && c.KSF.Identifier.Available()},
		{errors.New("invalid OPRF group id"), c.OPRF, c.OPRF.Available() && c.OPRF.OPRF().Available()},
		{errors.New("invalid AKE group id"), c.AKE, c.AKE.Available() && c.AKE.Group().Available()},
	}

	for _, test := range errorTests {
		if e := skipErrorOnCondition(t, err, test); e != nil {
			return e
		}
	}

	return fmt.Errorf("unrecognized error: %w", err)
}

func fuzzClientConfiguration(t *testing.T, c *opaque.Configuration) (*opaque.Client, error) {
	client, err := c.Client()
	if err != nil {
		if err = fuzzTestConfigurationError(t, c, err); err != nil {
			return nil, err
		}
	}
	if client == nil {
		t.Fatal("client is nil")
	}

	return client, nil
}

func fuzzServerConfiguration(t *testing.T, c *opaque.Configuration) (*opaque.Server, error) {
	server, err := c.Server()
	if err != nil {
		if err = fuzzTestConfigurationError(t, c, err); err != nil {
			return nil, err
		}
	}
	if server == nil {
		t.Fatal("server is nil")
	}

	return server, nil
}

func fuzzLoadVectors(path string) ([]*vector, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no vectors to read: %v", err)
	}

	var v []*vector
	err = json.Unmarshal(contents, &v)
	if err != nil {
		return nil, fmt.Errorf("no vectors to read: %v", err)
	}

	return v, nil
}

func FuzzConfiguration(f *testing.F) {
	// seed corpus
	loadVectorSeedCorpus(f, "")

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, h uint, o []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, o, ksfID, ake)

		if _, err := fuzzServerConfiguration(t, c); err != nil {
			t.Fatal(err)
		}

		if _, err := fuzzServerConfiguration(t, c); err != nil {
			t.Fatal(err)
		}
	})
}

func loadVectorSeedCorpus(f *testing.F, stage string) {
	// seed corpus
	vectors, err := fuzzLoadVectors("vectors.json")
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range vectors {
		if v.Config.Group == "curve25519" {
			continue
		}

		var input ByteToHex
		switch stage {
		case "":
			input = nil
		case "RegistrationRequest":
			input = v.Outputs.RegistrationRequest
		case "RegistrationResponse":
			input = v.Outputs.RegistrationResponse
		case "RegistrationRecord":
			input = v.Outputs.RegistrationRecord
		case "KE1":
			input = v.Outputs.KE1
		case "KE2":
			input = v.Outputs.KE2
		case "KE3":
			input = v.Outputs.KE3
		default:
			panic(nil)
		}

		f.Add([]byte(input),
			[]byte(v.Config.Context),
			uint(kdfToHash(v.Config.KDF)),
			uint(macToHash(v.Config.MAC)),
			uint(hashToHash(v.Config.Hash)),
			[]byte(v.Config.OPRF),
			byte(ksfToKSF(v.Config.KSF)),
			byte(groupToGroup(v.Config.Group)),
		)
	}

	// previous crashers
	f.Add([]byte("0"), []byte(""), uint(7), uint(37), uint(7), []byte{'\x05'}, byte('\x02'), byte('\x05'))
	f.Add([]byte("0"), []byte("0"), uint(13), uint(5), uint(5), []byte{'\x03'}, byte('\r'), byte('\x03'))
	f.Add([]byte("0"), []byte("0"), uint(13), uint(5), uint(5), []byte{'\a'}, byte('\x04'), byte('\x03'))
	f.Add(
		[]byte("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
		[]byte("0"),
		uint(7),
		uint(7),
		uint(7),
		[]byte{'\x01'},
		byte('\x03'),
		byte('\x01'),
	)
	f.Add(
		[]byte("00000000000000000000000000000000"),
		[]byte("0"),
		uint(7),
		uint(7),
		uint(7),
		[]byte{'\x01'},
		byte('\x03'),
		byte('\x06'),
	)
}

func inputToConfig(context []byte, kdf, mac, h uint, o []byte, ksfID, ake byte) *opaque.Configuration {
	return &opaque.Configuration{
		Context: context,
		KDF:     crypto.Hash(kdf),
		MAC:     crypto.Hash(mac),
		Hash:    crypto.Hash(h),
		OPRF:    oprfToGroup(oprf.Identifier(o)),
		KSF: opaque.KSFConfiguration{
			Identifier: ksf.Identifier(ksfID),
		},
		AKE: opaque.Group(ake),
	}
}

func FuzzDeserializeRegistrationRequest(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidBlindedData   = errors.New("blinded data is an invalid point")
	)

	loadVectorSeedCorpus(f, "RegistrationRequest")

	f.Fuzz(func(t *testing.T, r1, context []byte, kdf, mac, h uint, oprf []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, ksfID, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		_, err = server.Deserialize.RegistrationRequest(r1)
		if err != nil {
			conf := server.GetConf()
			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) &&
				len(r1) == conf.OPRF.Group().ElementLength() {
				t.Fatalf("got %q but input length is valid", errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidBlindedData.Error()) {
				if err := isValidOPRFPoint(conf, r1[:conf.OPRF.Group().ElementLength()], errInvalidBlindedData); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func FuzzDeserializeRegistrationResponse(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
		errInvalidServerPK      = errors.New("invalid server public key")
	)

	loadVectorSeedCorpus(f, "RegistrationResponse")

	f.Fuzz(func(t *testing.T, r2, context []byte, kdf, mac, h uint, oprf []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, ksfID, ake)
		client, err := c.Client()
		if err != nil {
			t.Skip()
		}

		_, err = client.Deserialize.RegistrationResponse(r2)
		if err != nil {
			conf := client.GetConf()
			maxResponseLength := conf.OPRF.Group().ElementLength() + conf.Group.ElementLength()

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(r2) == maxResponseLength {
				t.Fatalf(fmtGotValidInput, errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidEvaluatedData.Error()) {
				if err := isValidOPRFPoint(conf, r2[:conf.OPRF.Group().ElementLength()], errInvalidEvaluatedData); err != nil {
					t.Fatal(err)
				}
			}

			if strings.Contains(err.Error(), errInvalidServerPK.Error()) {
				if err := isValidAKEPoint(conf, r2[conf.OPRF.Group().ElementLength():], errInvalidServerPK); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func FuzzDeserializeRegistrationRecord(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidClientPK      = errors.New("invalid client public key")
	)

	loadVectorSeedCorpus(f, "RegistrationRecord")

	f.Fuzz(func(t *testing.T, r3, context []byte, kdf, mac, h uint, oprf []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, ksfID, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		conf := server.GetConf()

		_, err = server.Deserialize.RegistrationRecord(r3)
		if err != nil {
			maxMessageLength := conf.Group.ElementLength() + conf.Hash.Size() + conf.EnvelopeSize

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(r3) == maxMessageLength {
				t.Fatalf(fmtGotValidInput, errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidClientPK.Error()) {
				if err := isValidAKEPoint(conf, r3[:conf.Group.ElementLength()], errInvalidClientPK); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func FuzzDeserializeKE1(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidBlindedData   = errors.New("blinded data is an invalid point")
		errInvalidClientEPK     = errors.New("invalid ephemeral client public key")
	)

	loadVectorSeedCorpus(f, "KE1")

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, h uint, oprf []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, ksfID, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		_, err = server.Deserialize.KE1(ke1)
		if err != nil {
			conf := server.GetConf()
			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) &&
				len(ke1) == conf.OPRF.Group().ElementLength()+conf.NonceLen+conf.Group.ElementLength() {
				t.Fatalf("got %q but input length is valid", errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidBlindedData.Error()) {
				input := ke1[:conf.OPRF.Group().ElementLength()]
				if err := isValidOPRFPoint(conf, input, errInvalidBlindedData); err != nil {
					t.Fatal(err)
				}
			}

			if strings.Contains(err.Error(), errInvalidClientEPK.Error()) {
				input := ke1[conf.OPRF.Group().ElementLength()+conf.NonceLen:]
				if err := isValidOPRFPoint(conf, input, errInvalidClientEPK); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func isValidAKEPoint(conf *internal.Configuration, input []byte, err error) error {
	e := conf.Group.NewElement()
	if err2 := e.Decode(input); err2 == nil {
		if e.IsIdentity() {
			return errors.New("point is identity/infinity")
		}

		return fmt.Errorf("got %q but point is valid", err)
	}

	return nil
}

func isValidOPRFPoint(conf *internal.Configuration, input []byte, err error) error {
	e := conf.OPRF.Group().NewElement()
	if err2 := e.Decode(input); err2 == nil {
		if e.IsIdentity() {
			return errors.New("point is identity/infinity")
		}

		return fmt.Errorf("got %q but point is valid", err)
	}

	return nil
}

func FuzzDeserializeKE2(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
		errInvalidServerEPK     = errors.New("invalid ephemeral server public key")
	)

	loadVectorSeedCorpus(f, "KE2")

	f.Fuzz(func(t *testing.T, ke2, context []byte, kdf, mac, h uint, oprf []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, ksfID, ake)
		client, err := c.Client()
		if err != nil {
			t.Skip()
		}

		_, err = client.Deserialize.KE2(ke2)
		if err != nil {
			conf := client.GetConf()
			maxResponseLength := conf.OPRF.Group().
				ElementLength() +
				conf.NonceLen + conf.Group.ElementLength() + conf.EnvelopeSize

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) &&
				len(ke2) == maxResponseLength+conf.NonceLen+conf.Group.ElementLength()+conf.MAC.Size() {
				t.Fatalf(fmtGotValidInput, errInvalidMessageLength)
			}

			if strings.Contains(err.Error(), errInvalidEvaluatedData.Error()) {
				input := ke2[:conf.OPRF.Group().ElementLength()]
				if err := isValidOPRFPoint(conf, input, errInvalidEvaluatedData); err != nil {
					t.Fatal(err)
				}
			}

			if strings.Contains(err.Error(), errInvalidServerEPK.Error()) {
				input := ke2[conf.OPRF.Group().ElementLength()+conf.NonceLen:]
				if err := isValidAKEPoint(conf, input, errInvalidServerEPK); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func FuzzDeserializeKE3(f *testing.F) {
	// Error tested for
	errInvalidMessageLength := errors.New("invalid message length for the configuration")

	loadVectorSeedCorpus(f, "KE3")

	f.Fuzz(func(t *testing.T, ke3, context []byte, kdf, mac, h uint, oprf []byte, ksfID, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, ksfID, ake)
		server, err := c.Server()
		if err != nil {
			t.Skip()
		}

		_, err = server.Deserialize.KE3(ke3)
		if err != nil {
			conf := server.GetConf()
			maxMessageLength := conf.MAC.Size()

			if strings.Contains(err.Error(), errInvalidMessageLength.Error()) && len(ke3) == maxMessageLength {
				t.Fatalf(fmtGotValidInput, errInvalidMessageLength)
			}
		}
	})
}
