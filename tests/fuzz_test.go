//go:build go1.18
// +build go1.18

package opaque

import (
	"errors"
	"testing"

	"github.com/bytemare/opaque"
)

var (
	errInvalidMessageLength = errors.New("invalid message length")
	errInvalidBlindedData   = errors.New("blinded data is an invalid point")
	errInvalidClientEPK     = errors.New("invalid ephemeral client public key")
	errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
	errInvalidServerEPK     = errors.New("invalid ephemeral server public key")
	errInvalidServerPK      = errors.New("invalid server public key")
)

func FuzzDeserializeKE1(f *testing.F) {
	f.Fuzz(func(t *testing.T, ke1 []byte) {
		server := opaque.DefaultConfiguration().Server()
		_, err := server.DeserializeKE1(ke1)
		if err != nil {
			conf := server.Parameters
			if errors.Is(err, errInvalidMessageLength) && len(ke1) == conf.OPRFPointLength+conf.NonceLen+conf.AkePointLength {
				t.Fatalf("got %q but input is valid", errInvalidMessageLength)
			}

			if errors.Is(err, errInvalidBlindedData) {
				_, _err := conf.Group.NewElement().Decode(ke1[:conf.OPRFPointLength])
				if _err == nil {
					t.Fatalf("got %q but input is valid", errInvalidBlindedData)
				}
			}

			if errors.Is(err, errInvalidClientEPK) {
				_, _err := conf.Group.NewElement().Decode(ke1[conf.OPRFPointLength+conf.NonceLen:])
				if _err == nil {
					t.Fatalf("got %q but input is valid", errInvalidClientEPK)
				}
			}
		}
	})
}

//func FuzzRegistrationResponse(f *testing.F) {
//	f.Fuzz(func(t *testing.T, ke1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed, record, credID, idc []byte) {
//		server := opaque.DefaultConfiguration().Server()
//		dKE1, err := server.DeserializeKE1(ke1)
//		if err != nil {
//			t.Fatalf("deserializing KE1: %v", err)
//		}
//
//		dRecord, err := server.DeserializeRegistrationRecord(record)
//		if err != nil {
//			t.Fatalf("deserializing record: %v", err)
//		}
//
//		cred := &opaque.ClientRecord{
//			CredentialIdentifier: credID,
//			ClientIdentity:       idc,
//			RegistrationRecord:   dRecord,
//			TestMaskNonce:        nil,
//		}
//
//		_, err = server.LoginInit(dKE1, serverIdentity, serverSecretKey, serverPublicKey, oprfSeed, cred)
//		if err != nil {
//			t.Fatalf("login: %v", err)
//		}
//	})
//}
