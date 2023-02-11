// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2022 Daniel Bourdrez. All Rights Reserved.
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

const (
	fmtGotValidInput = "got %q but input is valid"
)

func fuzzTestConfigurationError(t *testing.T, c *opaque.Configuration, err error) {
	// Errors tested for
	var (
		errInvalidKDFid  = errors.New("invalid KDF id")
		errInvalidMACid  = errors.New("invalid MAC id")
		errInvalidHASHid = errors.New("invalid Hash id")
		errInvalidKSFid  = errors.New("invalid KSF id")
		errInvalidOPRFid = errors.New("invalid OPRF group id")
		errInvalidAKEid  = errors.New("invalid AKE group id")
	)

	if strings.Contains(err.Error(), errInvalidKDFid.Error()) {
		if hash.Hashing(c.KDF).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidKDFid, c.KDF)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidMACid.Error()) {
		if hash.Hashing(c.MAC).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidMACid, c.MAC)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidHASHid.Error()) {
		if hash.Hashing(c.Hash).Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidHASHid, c.Hash)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidKSFid.Error()) {
		if c.KSF.Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidKSFid, c.KSF)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidOPRFid.Error()) {
		if c.OPRF.OPRF().Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidOPRFid, c.OPRF)
		}
		t.Skip()
	}
	if strings.Contains(err.Error(), errInvalidAKEid.Error()) {
		if c.AKE.Group().Available() {
			t.Fatalf("got %q but input is valid: %q", errInvalidAKEid, c.AKE)
		}
		t.Skip()
	}

	t.Fatalf("Unrecognized error: %q", err)
}

func fuzzClientConfiguration(t *testing.T, c *opaque.Configuration) *opaque.Client {
	client, err := c.Client()
	if err != nil {
		fuzzTestConfigurationError(t, c, err)
	}
	if client == nil {
		t.Fatal("server is nil")
	}

	return client
}

func fuzzServerConfiguration(t *testing.T, c *opaque.Configuration) *opaque.Server {
	server, err := c.Server()
	if err != nil {
		fuzzTestConfigurationError(t, c, err)
	}
	if server == nil {
		t.Fatal("server is nil")
	}

	return server
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

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, h uint, o []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, o, _ksf, ake)
		_ = fuzzServerConfiguration(t, c)
		_ = fuzzClientConfiguration(t, c)
	})
}

func loadVectorSeedCorpus(f *testing.F, stage string) {
	// seed corpus
	vectors, err := fuzzLoadVectors("vectors.json")
	if err != nil {
		log.Fatal(err)
	}

	for _, v := range vectors {
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

func inputToConfig(context []byte, kdf, mac, h uint, o []byte, _ksf, ake byte) *opaque.Configuration {
	return &opaque.Configuration{
		Context: context,
		KDF:     crypto.Hash(kdf),
		MAC:     crypto.Hash(mac),
		Hash:    crypto.Hash(h),
		OPRF:    oprfToGroup(oprf.Identifier(o)),
		KSF:     ksf.Identifier(_ksf),
		AKE:     opaque.Group(ake),
	}
}

func FuzzDeserializeRegistrationRequest(f *testing.F) {
	// Errors tested for
	var (
		errInvalidMessageLength = errors.New("invalid message length for the configuration")
		errInvalidBlindedData   = errors.New("blinded data is an invalid point")
	)

	loadVectorSeedCorpus(f, "RegistrationRequest")

	f.Fuzz(func(t *testing.T, r1, context []byte, kdf, mac, h uint, oprf []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
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

	f.Fuzz(func(t *testing.T, r2, context []byte, kdf, mac, h uint, oprf []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
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

	f.Fuzz(func(t *testing.T, r3, context []byte, kdf, mac, h uint, oprf []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
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

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, h uint, oprf []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
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
				if err := isValidOPRFPoint(conf, ke1[:conf.OPRF.Group().ElementLength()], errInvalidBlindedData); err != nil {
					t.Fatal(err)
				}
			}

			if strings.Contains(err.Error(), errInvalidClientEPK.Error()) {
				if err := isValidOPRFPoint(conf, ke1[conf.OPRF.Group().ElementLength()+conf.NonceLen:], errInvalidClientEPK); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func isValidAKEPoint(conf *internal.Configuration, input []byte, err error) error {
	e := conf.Group.NewElement()
	if _err := e.Decode(input); _err == nil {
		if e.IsIdentity() {
			return errors.New("point is identity/infinity")
		}

		return fmt.Errorf("got %q but point is valid", err)
	}

	return nil
}

func isValidOPRFPoint(conf *internal.Configuration, input []byte, err error) error {
	e := conf.OPRF.Group().NewElement()
	if _err := e.Decode(input); _err == nil {
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

	f.Fuzz(func(t *testing.T, ke2, context []byte, kdf, mac, h uint, oprf []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
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
				if err := isValidOPRFPoint(conf, ke2[:conf.OPRF.Group().ElementLength()], errInvalidEvaluatedData); err != nil {
					t.Fatal(err)
				}
			}

			if strings.Contains(err.Error(), errInvalidServerEPK.Error()) {
				if err := isValidAKEPoint(conf, ke2[conf.OPRF.Group().ElementLength()+conf.NonceLen:], errInvalidServerEPK); err != nil {
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

	f.Fuzz(func(t *testing.T, ke3, context []byte, kdf, mac, h uint, oprf []byte, _ksf, ake byte) {
		c := inputToConfig(context, kdf, mac, h, oprf, _ksf, ake)
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
