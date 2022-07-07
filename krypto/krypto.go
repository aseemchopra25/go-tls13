package krypto

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

// TODO: Make Private Key Private

type KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

var NewKeyPair = KeyPair{}

func (keyPair *KeyPair) createPrivateKey() {
	rand.Read(NewKeyPair.PrivateKey[:])
}

func (keyPair *KeyPair) createPublicKey() {
	// https://pkg.go.dev/golang.org/x/crypto/curve25519#X25519
	y, err := curve25519.X25519(NewKeyPair.PrivateKey[:], curve25519.Basepoint)
	copy(NewKeyPair.PublicKey[:], y)
	checkerr(err)
}

func KeyGen() {
	NewKeyPair.createPrivateKey()
	NewKeyPair.createPublicKey()
}
