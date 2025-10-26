// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2025 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package opaque_test

import (
	"reflect"
	"testing"
	"unsafe"

	"github.com/bytemare/ecc"

	"github.com/bytemare/opaque"
	"github.com/bytemare/opaque/internal"
	internalKSF "github.com/bytemare/opaque/internal/ksf"
)

func setClientSecretKeyShare(t *testing.T, client *opaque.Client, share *ecc.Scalar) {
	t.Helper()
	setClientUnexported(t, client, "ake", "SecretKeyShare", share)
}

func setClientOPRFBlind(t *testing.T, client *opaque.Client, blind *ecc.Scalar) {
	t.Helper()
	setClientUnexported(t, client, "oprf", "blind", blind)
}

func setClientKE1(t *testing.T, client *opaque.Client, data []byte) {
	t.Helper()
	setClientUnexported(t, client, "ake", "ke1", data)
}

func getClientSecretKeyShare(t *testing.T, client *opaque.Client) *ecc.Scalar {
	t.Helper()
	elem := reflect.ValueOf(client).Elem()
	field := elem.FieldByName("ake").FieldByName("SecretKeyShare")
	value := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
	if value.IsNil() {
		return nil
	}
	return value.Interface().(*ecc.Scalar)
}

func setClientUnexported[T any](t *testing.T, client *opaque.Client, structName, fieldName string, value T) {
	t.Helper()

	elem := reflect.ValueOf(client).Elem()
	field := elem.FieldByName(structName).FieldByName(fieldName)
	if !field.IsValid() {
		t.Fatalf("invalid field %s.%s", structName, fieldName)
	}

	reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Set(reflect.ValueOf(value))
}

func TestClient_GenerateKE1_PreExistingSecretShare(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client := getClient(t2, conf)
		setClientSecretKeyShare(t2, client, conf.internal.MakeSecretKeyShare(nil))

		expectErrors(t, func() error {
			_, err := client.GenerateKE1(password)
			return err
		}, opaque.ErrClientState, internal.ErrClientPreExistingKeyShare)
	})
}

func TestClient_GenerateKE3_StateChecks(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		type testCase struct {
			name     string
			mutate   func(*opaque.Client)
			options  []*opaque.ClientOptions
			expected []error
		}

		cases := []testCase{
			{
				name: "missing-blind",
				mutate: func(c *opaque.Client) {
					setClientOPRFBlind(t2, c, nil)
				},
				expected: []error{opaque.ErrClientOptions, internal.ErrNoOPRFBlind},
			},
			{
				name: "missing-secret-share",
				mutate: func(c *opaque.Client) {
					setClientSecretKeyShare(t2, c, nil)
				},
				expected: []error{opaque.ErrClientOptions, internal.ErrClientNoKeyShare},
			},
			{
				name: "missing-ke1",
				mutate: func(c *opaque.Client) {
					setClientKE1(t2, c, nil)
				},
				expected: []error{opaque.ErrClientOptions, internal.ErrKE1Missing},
			},
			{
				name: "options-provided-no-blind",
				mutate: func(c *opaque.Client) {
					setClientOPRFBlind(t2, c, nil)
				},
				options:  []*opaque.ClientOptions{{}},
				expected: []error{opaque.ErrClientOptions, internal.ErrNoOPRFBlind},
			},
		}

		for _, tc := range cases {
			t2.Run(tc.name, func(t3 *testing.T) {
				client, server := setup(t3, conf)
				record := registration(t3, client, server, password, credentialIdentifier, clientIdentity, serverIdentity)

				client.ClearState()
				ke1, err := client.GenerateKE1(password)
				if err != nil {
					t3.Fatalf("GenerateKE1 failed: %v", err)
				}

				ke2, _, err := server.GenerateKE2(ke1, record)
				if err != nil {
					t3.Fatalf("GenerateKE2 failed: %v", err)
				}

				tc.mutate(client)

				expectErrors(t, func() error {
					_, _, _, err := client.GenerateKE3(ke2, nil, nil, tc.options...)
					return err
				}, tc.expected...)
			})
		}
	})
}

func TestClient_GenerateKE3_ParseOptionsErrors(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		type testCase struct {
			name     string
			mutate   func(*opaque.Client)
			options  *opaque.ClientOptions
			expected []error
		}

		cases := []testCase{
			{
				name: "options-no-blind",
				mutate: func(c *opaque.Client) {
					setClientOPRFBlind(t2, c, nil)
				},
				options:  &opaque.ClientOptions{},
				expected: []error{opaque.ErrClientOptions, internal.ErrNoOPRFBlind},
			},
			{
				name: "invalid-ksf-parameters",
				mutate: func(c *opaque.Client) {
					setClientSecretKeyShare(t2, c, nil)
				},
				options: &opaque.ClientOptions{
					KSFParameters: []int{1},
					AKE: &opaque.AKEOptions{
						SecretKeyShare: conf.internal.Group.NewScalar().Random(),
					},
				},
				expected: []error{opaque.ErrClientOptions, internalKSF.ErrParameters},
			},
		}

		for _, tc := range cases {
			t2.Run(tc.name, func(t3 *testing.T) {
				client, server := setup(t3, conf)
				record := registration(t3, client, server, password, credentialIdentifier, clientIdentity, serverIdentity)

				client.ClearState()
				ke1, err := client.GenerateKE1(password)
				if err != nil {
					t3.Fatalf("GenerateKE1 failed: %v", err)
				}

				ke2, _, err := server.GenerateKE2(ke1, record)
				if err != nil {
					t3.Fatalf("GenerateKE2 failed: %v", err)
				}

				tc.mutate(client)

				expectErrors(t, func() error {
					_, _, _, err := client.GenerateKE3(ke2, nil, nil, tc.options)
					return err
				}, tc.expected...)
			})
		}
	})
}

func TestClient_GenerateKE3_CustomSecretShareOption(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		record := registration(t2, client, server, password, credentialIdentifier, clientIdentity, serverIdentity)

		client.ClearState()
		ke1, err := client.GenerateKE1(password)
		if err != nil {
			t2.Fatalf("GenerateKE1 failed: %v", err)
		}

		ke2, _, err := server.GenerateKE2(ke1, record)
		if err != nil {
			t2.Fatalf("GenerateKE2 failed: %v", err)
		}

		share := getClientSecretKeyShare(t2, client)
		setClientSecretKeyShare(t2, client, nil)

		expectErrors(t, func() error {
			_, _, _, err := client.GenerateKE3(
				ke2,
				nil,
				nil,
				&opaque.ClientOptions{
					AKE: &opaque.AKEOptions{SecretKeyShare: share},
				},
			)
			return err
		}, opaque.ErrAuthentication, internal.ErrEnvelopeInvalidMac)
	})
}

func TestServer_GenerateKE2_ServerOptions(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		recordBuilder := func() (*opaque.Client, *opaque.Server, *opaque.ClientRecord) {
			client, server := setup(t2, conf)
			rec := registration(t2, client, server, password, credentialIdentifier, clientIdentity, serverIdentity)
			return client, server, rec
		}

		{
			client, server, record := recordBuilder()
			client.ClearState()
			ke1, err := client.GenerateKE1(password)
			if err != nil {
				t2.Fatalf("GenerateKE1 failed: %v", err)
			}

			if _, _, err = server.GenerateKE2(
				ke1,
				record,
				&opaque.ServerOptions{ClientOPRFKey: conf.internal.Group.NewScalar().Random()},
			); err != nil {
				t2.Fatalf("GenerateKE2 with custom client key failed: %v", err)
			}
		}

		{
			client, server, record := recordBuilder()
			client.ClearState()
			ke1, err := client.GenerateKE1(password)
			if err != nil {
				t2.Fatalf("GenerateKE1 failed: %v", err)
			}

			if _, _, err = server.GenerateKE2(ke1, record, &opaque.ServerOptions{AKE: nil}); err != nil {
				t2.Fatalf("GenerateKE2 with nil AKE options failed: %v", err)
			}
		}

		{
			client, server, record := recordBuilder()
			client.ClearState()
			ke1, err := client.GenerateKE1(password)
			if err != nil {
				t2.Fatalf("GenerateKE1 failed: %v", err)
			}

			if _, _, err = server.GenerateKE2(
				ke1,
				record,
				&opaque.ServerOptions{
					AKE: &opaque.AKEOptions{SecretKeyShare: conf.internal.Group.NewScalar().Random()},
				},
			); err != nil {
				t2.Fatalf("GenerateKE2 with explicit secret share failed: %v", err)
			}
		}
	})
}

func TestClient_RegistrationFinalize_EnvelopeLength(t *testing.T) {
	testAll(t, func(t2 *testing.T, conf *configuration) {
		client, server := setup(t2, conf)
		req, err := client.RegistrationInit(password)
		if err != nil {
			t2.Fatalf("RegistrationInit failed: %v", err)
		}

		resp, err := server.RegistrationResponse(req, credentialIdentifier, nil)
		if err != nil {
			t2.Fatalf("RegistrationResponse failed: %v", err)
		}

		nonce := internal.RandomBytes(conf.internal.NonceLen)
		options := &opaque.ClientOptions{
			EnvelopeNonce:       nonce,
			EnvelopeNonceLength: len(nonce),
		}

		if _, _, err = client.RegistrationFinalize(resp, nil, nil, options); err != nil {
			t2.Fatalf("RegistrationFinalize failed: %v", err)
		}
	})
}

func TestIdentityKSFParameterizeNoOp(t *testing.T) {
	internalKSF.IdentityKSF{}.Parameterize(1, 2, 3)
}
