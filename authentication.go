package opaque

import (
	"github.com/bytemare/cryptotools/encoding"
)

func (c *Client) credentialRequest(password []byte) *CredentialRequest {
	m, _ := c.oprfStart(password)
	return &CredentialRequest{Data: m}
}

func (c *Client) AuthenticationStart(password, info1 []byte, enc encoding.Encoding) *ClientInit {
	credreq := c.credentialRequest(password)
	ke1 := c.ake.Start(c.nonceLen, enc)

	creq, err := enc.Encode(credreq)
	if err != nil {
		panic(err)
	}

	c.meta.CredReq = creq
	c.meta.Info1 = info1

	return &ClientInit{
		Creq:  *credreq,
		KE1:   ke1,
		Info1: info1,
	}
}

func (c *Client) AuthenticationFinalize(creds Credentials, resp *ServerResponse, info3 []byte, enc encoding.Encoding) (*ClientFinish, []byte, error) {
	secretCreds, exportKey, err := c.recoverCredentials(creds, resp, enc)
	if err != nil {
		return nil, nil, err
	}

	c.clientMetaData(creds, resp, secretCreds.Sku, enc)

	ke3, einfo3, err := c.ake.Finalize(c.meta, secretCreds.Sku, creds.ServerPublicKey(), resp.KE2, resp.Info2, resp.EInfo2, info3, enc)
	if err != nil {
		return nil, nil, err
	}

	return &ClientFinish{
		KE3:    ke3,
		Info3:  info3,
		EInfo3: einfo3,
	}, exportKey, nil
}

func (c *Client) SessionKey() []byte {
	return c.ake.SessionKey()
}

func (s *Server) AuthenticationResponse(req *ClientInit, env *Envelope, idu, pku, ids, info1, info2 []byte, enc encoding.Encoding) *ServerResponse {
	evaluation := s.evaluate(req.Creq.Data)

	z, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	credResp := CredentialResponse{
		Data:     z,
		Pks:      s.akePubKey,
		Envelope: *env,
	}

	s.serverMetaData(&req.Creq, &credResp, pku, idu, ids, info1, enc)

	ke2, einfo2, err := s.ake.Response(s.meta, s.nonceLen, pku, req.KE1, info2, enc)
	if err != nil {
		panic(err)
	}

	return &ServerResponse{
		Cresp: credResp,
		KE2:    ke2,
		Info2:  info2,
		EInfo2: einfo2,
	}
}

func (s *Server) AuthenticationFinalize(req *ClientFinish, enc encoding.Encoding) error {
	return s.ake.Finalize(req.Info3, req.EInfo3, req.KE3, enc)
}

func (s *Server) SessionKey() []byte {
	return s.ake.SessionKey()
}