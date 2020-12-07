package new

import (
	"bytes"
	"fmt"
	"github.com/bytemare/cryptotools"
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/new/ake/threeDH"
	"github.com/bytemare/opaque/new/message"
	"github.com/bytemare/opaque/new/proto"
	"github.com/bytemare/voprf"
	"testing"
)

func TestDraft(t *testing.T) {
	idu := []byte("user")
	password := []byte("password")
	ids := []byte("server")
	cs, err := cryptotools.New(nil, []byte("OPAQUE00-TEST1234"))
	if err != nil {
		panic(err)
	}
	enc := encoding.JSON

	sks := cs.NewScalar().Random()
	pks := cs.Base().Mult(sks)

	sku := cs.NewScalar().Random()
	pku := cs.Base().Mult(sku)

	/*
		Registration
	*/

	// Client
	reqreq, _ := proto.CreateRegistrationRequest(password)

	// Server
	reqresp := proto.CreateRegistrationResponse(reqreq, sks.Bytes(), pks.Bytes())

	// Client
	upload, export := proto.FinalizeRequest(nil, nil, nil, nil, reqresp)

	/*
		Authentication + Key Exchange
	*/

	//
	credreq, _ := proto.CreateCredentialRequest(password)
	reqEnc, _ := enc.Encode(credreq)
	//ke1, esku := threeDH.ClientInit(cs.Group)
	dhClient := threeDH.NewClient(voprf.RistrettoSha512, cs.Group, cs.Hash)
	ke1 := dhClient.Start(32)

	KE1, _ := enc.Encode(ke1)

	message1 := message.ClientInit{
		CredentialRequest: credreq,
		KE1:               KE1,
	}

	//
	credresp := proto.CreateCredentialResponse(message1.CredentialRequest, sks.Bytes(), pku.Bytes(), upload.Envelope)
	respEnc, _ := enc.Encode(credresp)
	ke1dec, _ := threeDH.DecodeKe1(message1.KE1, enc)
	//ke2, server := threeDH.ServerResponse(cs.Group, cs.Hash, 32, reqEnc, respEnc, idu, ids, pku.Bytes(), sks.Bytes(), ke1dec)
	dhServer := threeDH.NewServer(voprf.RistrettoSha512, cs.Group, cs.Hash, sks.Bytes())
	ke2, err := dhServer.Response(32, 32, reqEnc, respEnc, idu, ids, pku.Bytes(), ke1dec)
	if err != nil {
		panic(err)
	}
	KE2, _ := enc.Encode(ke2)

	message2 := message.ServerResponse{
		CredentialResponse: credresp,
		KE2:                KE2,
		Info2:              nil,
		EInfo2:             nil,
	}

	//
	_, export2 := proto.RecoverCredentials(nil, nil, nil, credresp)
	ke2dec, _ := threeDH.DecodeKe2(message2.KE2, enc)
	ke3, err := dhClient.Finalize(reqEnc, respEnc, sku.Bytes(), pks.Bytes(), idu, ids, ke1dec, ke2dec, 32)
	if err != nil {
		panic(err)
	}
	KE3, _ := enc.Encode(ke3)

	message3 := message.ClientFinish{
		KE3:    KE3,
		Info3:  nil,
		EInfo3: nil,
	}

	//
	decke3, _ := threeDH.DecodeKe3(message3.KE3, enc)
	success := dhServer.Finalize(decke3)

	if bytes.Equal(export, export2) {
		fmt.Println("Export keys match !!!")
	} else {
		fmt.Println("Export keys don't match.")
	}

	if success {
		fmt.Println("3DH mac validated !!!")
	} else {
		fmt.Println("3DH mac not validated.")
	}

	if bytes.Equal(dhClient.SessionSecret(), dhServer.SessionSecret()) {
		fmt.Println("Session secrets match !!!")
	} else {
		fmt.Println("Session secrets don't match.")
	}

	// Output: Export keys match !!!
}
