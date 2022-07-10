package session

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

var NewKeyPair KeyPair

type ServerHello struct {
	Random []byte
	Pubkey []byte
}

var NewServerHello ServerHello

type Secret struct {
	SS   []byte
	HS   []byte
	CHS  []byte
	SHS  []byte
	CHK  []byte
	CHIV []byte
	SHK  []byte
	SHIV []byte
}

var Sekret Secret

type Session struct {
	CHBytes  []byte
	SHBytes  []byte
	SHSBytes []byte
}

var NewSesh = Session{}
