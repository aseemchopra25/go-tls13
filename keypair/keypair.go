package keypair

import (
	"crypto/rand"
	"log"

	"golang.org/x/crypto/curve25519"
)

func checkerr(err error) {
	if err != nil {
		log.Fatal("Error: ", err)
	}
}

type KeyPair struct {
	PublicKey  []byte
	PrivateKey []byte
}

var NewKeyPair = KeyPair{}

func createPrivateKey() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

func createPublicKey(privateKey []byte) []byte {

	y, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	checkerr(err)
	return y
}

func Generate() {
	// entry point from main.go

	NewKeyPair.PrivateKey = createPrivateKey()
	NewKeyPair.PublicKey = createPublicKey(NewKeyPair.PrivateKey)
}
