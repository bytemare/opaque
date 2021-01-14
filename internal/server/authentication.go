package server

import (
	"bytes"

	"github.com/bytemare/opaque/internal"

	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/opaque/envelope"
	"github.com/bytemare/opaque/message"
)

func (s *Server) AuthenticationResponse(req *message.ClientInit, env *envelope.Envelope, creds message.Credentials, info1, info2, pku []byte, enc encoding.Encoding) (credResp *message.CredentialResponse, ke2, einfo2 []byte, err error) {
	if !bytes.Equal(creds.ServerPublicKey(), s.AkePubKey) {
		return nil, nil, nil, internal.ErrParamServerPubKey
	}

	if pku == nil {
		return nil, nil, nil, internal.ErrParamServerNilPubKey
	}

	evaluation := s.evaluate(req.Creq.Data)

	z, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	credResp = &message.CredentialResponse{
		Data:     z,
		Pks:      s.AkePubKey,
		Envelope: *env,
	}

	s.serverMetaData(creds, &req.Creq, credResp, info1, pku, enc)

	ke2, einfo2, err = s.Ake.Response(s.meta, s.nonceLen, pku, req.KE1, info2, enc)
	if err != nil {
		panic(err)
	}

	return credResp, ke2, einfo2, nil
}
