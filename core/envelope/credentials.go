package envelope

type SecretCredentials struct {
	Sku []byte
}

func (s *SecretCredentials) Serialize() []byte {
	return s.Sku
}

func DeserializeSecretCredentials(input []byte) *SecretCredentials {
	return &SecretCredentials{input}
}

type CleartextCredentials interface {
	Serialize() []byte
}

func encodeClearTextCredentials(idu, ids, pks []byte, mode Mode) []byte {
	switch mode {
	case Base:
		return newBaseClearTextCredentials(pks).Serialize()
	case CustomIdentifier:
		return newCustomClearTextCredentials(pks, idu, ids).Serialize()
	default:
		panic("invalid mode")
	}
}

type Credentials struct {
	Sk, Pk, Idu, Ids, Nonce []byte
}
