package opaque

import (
	"github.com/bytemare/cryptotools/encoding"
	"github.com/bytemare/cryptotools/utils"
	"github.com/bytemare/opaque/records"
)

func (c *Client) RegistrationStart(password []byte) *RegistrationRequest {
	m, _ := c.oprfStart(password)
	return &RegistrationRequest{Data: m}
}

func (c *Client) RegistrationFinalize(sku, pku []byte, creds Credentials, resp *RegistrationResponse, enc encoding.Encoding) (*RegistrationUpload, []byte, error) {
	envelope, exportKey, err := c.buildEnvelope(sku, creds, resp, enc)
	if err != nil {
		return nil, nil, err
	}

	return &RegistrationUpload{
		Envelope: *envelope,
		Pku:      pku,
	}, exportKey, nil
}

func (s *Server) RegistrationResponse(req *RegistrationRequest, enc encoding.Encoding) *RegistrationResponse {
	evaluation := s.evaluate(req.Data)

	z, err := evaluation.Encode(enc)
	if err != nil {
		panic(err)
	}

	response := &RegistrationResponse{
		Data: z,
		Pks:  s.akePubKey,
	}

	return response
}

func (s *Server) RegistrationFinalize(username, uuid []byte, up *RegistrationUpload, enc encoding.Encoding) (*records.UserRecord, *records.OprfRecord, *records.AkeRecord, error){
	or := s.getOprfRecord()
	ar := s.getAkeRecord()

	env, err := up.Envelope.Encode(enc)
	if err != nil {
		return nil, nil, nil, err
	}

	return &records.UserRecord{
		HumanUserID:   username,
		UUID:          uuid,
		UserPublicKey: up.Pku,
		EnvelopeMode:  bool(up.Envelope.Contents.Mode),
		Envelope:      env,
		ServerOprfID:  or.ID,
		ServerAkeID:   ar.ID,
	}, or, ar, nil
}


func (s *Server) getOprfRecord() *records.OprfRecord {
	return &records.OprfRecord{
		ID:          utils.RandomBytes(32),
		Ciphersuite: s.oprf.Ciphersuite(),
		OprfKey:     s.oprf.PrivateKey(),
	}
}

func (s *Server) getAkeRecord() *records.AkeRecord {
	return &records.AkeRecord{
		ID:  utils.RandomBytes(32),
		Ake: s.ake.Identifier(),
		Group:     s.oprf.Ciphersuite().Group(),
		// hash
		SecretKey: s.ake.PrivateKey(),
		PublicKey: s.akePubKey,
	}
}