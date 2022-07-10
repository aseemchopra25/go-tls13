package main

import (
	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/server"
)

func main() {
	// 1. Create KeyPair for X25519
	krypto.GenerateKeyPair()

	// 2. Send Client Hello
	client.SendHello("www.chopraaseem.com")

	// 3. Read Server Hello
	server.ReadServerHello()

	// 4. Key Derivation
	krypto.KeyDerivation()

	// fine till now

	// 5. Read Server Handshake
	server.ReadServerHandshake()

}
