package session

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

var NewKeyPair = KeyPair{}

type ServerHello struct {
	Random []byte
	Pubkey []byte
}

var NewServerHello = ServerHello{}

type Secret struct {
	// Handshake
	SS   []byte
	HS   []byte
	CHS  []byte
	SHS  []byte
	CHK  []byte
	CHIV []byte
	SHK  []byte
	SHIV []byte

	// Application
	CAK  []byte
	CAIV []byte
	SAK  []byte
	SAIV []byte

	// Finished
	CHF []byte
}

var Sekret = Secret{}

type Session struct {
	CHBytes  []byte
	SHBytes  []byte
	SHSBytes []byte
	CHFBytes []byte
}

var NewSesh = Session{}

type Counter struct {
	Sent uint8
	Recv uint8
}

var NewCounter = Counter{}
