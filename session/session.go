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
	// Handshake Secrets
	SS  []byte
	HS  []byte
	CHS []byte
	SHS []byte

	// Handshake Keys & IV
	CHK  []byte
	CHIV []byte
	SHK  []byte
	SHIV []byte

	// Application Keys & IV
	CAK  []byte
	CAIV []byte
	SAK  []byte
	SAIV []byte

	// Finished
	CHF []byte
	SHF []byte
}

var Sekret = Secret{}

type Session struct {
	CHBytes  []byte
	SHBytes  []byte
	SHSBytes []byte
	CHFBytes []byte
	SEEBytes []byte
	SCBytes  []byte
	SCVBytes []byte
	SCCBytes []byte
	// SHFBytes  []byte

}

var NewSesh = Session{}

type Counter struct {
	Sent uint8
	Recv uint8
}

var HSCounter = Counter{}
var ACounter = Counter{}
