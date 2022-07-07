package krypto

import (
	"fmt"
	"testing"
)

// t.Errorf("Error: %q", x)
func TestPrivateKey(t *testing.T) {
	KeyGen()
	fmt.Println(NewKeyPair.PrivateKey)
	for _, v := range NewKeyPair.PrivateKey {
		if v != 0 {
			return
		}
	}
	t.Errorf("Error: Empty Private Key")

}

func TestPublicKey(t *testing.T) {
	fmt.Println(NewKeyPair.PublicKey)
	KeyGen()
	for _, v := range NewKeyPair.PublicKey {
		if v != 0 {
			return
		}
	}
	t.Errorf("Error: Empty Private Key")

}
