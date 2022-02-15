//go:build go1.18
// +build go1.18

package opaque

import (
	"crypto"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/bytemare/crypto/ksf"

	"github.com/bytemare/opaque"
)

var (
	errInvalidBlindedData   = errors.New("blinded data is an invalid point")
	errInvalidClientEPK     = errors.New("invalid ephemeral client public key")
	errInvalidEvaluatedData = errors.New("invalid OPRF evaluation")
	errInvalidServerEPK     = errors.New("invalid ephemeral server public key")
	errInvalidServerPK      = errors.New("invalid server public key")
)

func FuzzDeserializeKE1(f *testing.F) {
	// seed corpus
	kes1messages := []string{
		"c021ab3bca8c7c7949f7090d2af149523c5029d6c5c45b59997f8c306ccbdf75400ceac0fbfb16005928335518be6f930a113c6c0814521262e17ecc3cdc9f91da25553da9ac142b36332dbd487713ae6712432fb317a6e00b2b17525bbe6912",
		"7002a52fa6c2916c49c1fff952e818e458c7f7799139b243918c97758f463a47e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421b1d63d7a2cfd90961b35150da8824e44af3cdc7a29880ff532751b7ccc6a8875ac14e08964942473de9484f7b",
		"0226bc3aeccce9c813eaec852599fe76eafe611467a054e738441d4a3b7922aaba72721898ef81cc0a76a0b5508f2f7bb817e86f1dd05ca013190a68602c7af25f03a51c7c3d3a69f5217c0f8de4efa242b0cf4ba35cc67c820e57b69e7a4f53cd69",
		"03ff69ee0b845955eafc817acf721fdecccc94977c4aa0841ec33bf5060375e3a4a2912bab9b6a62cddf7d5e3209a2859e5947586f69259e0708bdfab794f689ee038744dec9da18441e1ef78ff9b2e5d62c713e56eee7aa326a9be577365f919d6c",
		"943a149cf304878367fa2dce5cb30eac23cfd1358e5cc0efdbd4361a9e7bd72dc26fead2a8b3d5910e25fd29402530b5c7e852585f843f3b939993624b8a7c3b581062b0e8e90db4798adbb49581f016034e0855b6d6199aceb56a71c9bd4866",
		"0258384d63ae4bbddde6d00d41b0e7174695ff6234563e16fc284aa589c7de93f9b8bb2700cdd47e339d95404519f2fb3da58c93d84cbb4d51de6757a31919382b02630e46a94b7f8f66071d24794c37f605055c098afc04d637caf9b1bc714bd15c",
	}

	configs := []*opaque.Configuration{
		opaque.DefaultConfiguration(),
		{Context: nil, KDF: crypto.SHA256, MAC: crypto.SHA256, Hash: crypto.SHA256, OPRF: opaque.P256Sha256, KSF: ksf.Argon2id, AKE: opaque.P256Sha256},
		{Context: nil, KDF: crypto.SHA384, MAC: crypto.SHA384, Hash: crypto.SHA384, OPRF: opaque.P384Sha512, KSF: ksf.PBKDF2Sha512, AKE: opaque.P384Sha512},
		{Context: nil, KDF: crypto.SHA512, MAC: crypto.SHA512, Hash: crypto.SHA512, OPRF: opaque.P521Sha512, KSF: ksf.Scrypt, AKE: opaque.P521Sha512},
	}

	for _, s := range kes1messages {
		b, err := hex.DecodeString(s)
		if err != nil {
			f.Fatal(err)
		}

		for _, c := range configs {
			f.Add(b, c.Context, uint(c.KDF), uint(c.MAC), uint(c.Hash), byte(c.OPRF), byte(c.KSF), byte(c.AKE))
		}
	}

	f.Fuzz(func(t *testing.T, ke1, context []byte, kdf, mac, hash uint, oprf, _ksf, ake byte) {
		c := &opaque.Configuration{
			Context: context,
			KDF:     crypto.Hash(kdf),
			MAC:     crypto.Hash(mac),
			Hash:    crypto.Hash(hash),
			OPRF:    opaque.Group(oprf),
			KSF:     ksf.Identifier(_ksf),
			AKE:     opaque.Group(ake),
		}
		server := c.Server()
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
//	// seed corpus
//	corpus := []string{
//		"c021ab3bca8c7c7949f7090d2af149523c5029d6c5c45b59997f8c306ccbdf75400ceac0fbfb16005928335518be6f930a113c6c0814521262e17ecc3cdc9f91da25553da9ac142b36332dbd487713ae6712432fb317a6e00b2b17525bbe6912",
//		"7002a52fa6c2916c49c1fff952e818e458c7f7799139b243918c97758f463a47e8f5bbbaa7ad3dce15eb299eb2a5b34875ff421b1d63d7a2cfd90961b35150da8824e44af3cdc7a29880ff532751b7ccc6a8875ac14e08964942473de9484f7b",
//		"0226bc3aeccce9c813eaec852599fe76eafe611467a054e738441d4a3b7922aaba72721898ef81cc0a76a0b5508f2f7bb817e86f1dd05ca013190a68602c7af25f03a51c7c3d3a69f5217c0f8de4efa242b0cf4ba35cc67c820e57b69e7a4f53cd69",
//		"03ff69ee0b845955eafc817acf721fdecccc94977c4aa0841ec33bf5060375e3a4a2912bab9b6a62cddf7d5e3209a2859e5947586f69259e0708bdfab794f689ee038744dec9da18441e1ef78ff9b2e5d62c713e56eee7aa326a9be577365f919d6c",
//		"943a149cf304878367fa2dce5cb30eac23cfd1358e5cc0efdbd4361a9e7bd72dc26fead2a8b3d5910e25fd29402530b5c7e852585f843f3b939993624b8a7c3b581062b0e8e90db4798adbb49581f016034e0855b6d6199aceb56a71c9bd4866",
//		"0258384d63ae4bbddde6d00d41b0e7174695ff6234563e16fc284aa589c7de93f9b8bb2700cdd47e339d95404519f2fb3da58c93d84cbb4d51de6757a31919382b02630e46a94b7f8f66071d24794c37f605055c098afc04d637caf9b1bc714bd15c",
//	}
//
//	for _, s := range corpus {
//		b, err := hex.DecodeString(s)
//		if err != nil {
//			f.Fatal(err)
//		}
//		f.Add(b)
//	}
//
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
//
