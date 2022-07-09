package main

import (
	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/keypair"
	"github.com/aseemchopra25/go-toy-tls/server"
)

func main() {
	// 1. Create KeyPair for X25519
	keypair.Generate()

	// 2. Send Client Hello
	client.SendHello("www.chopraaseem.com")

	// 5. Read Server Hello
	server.ReadServerHello()
}
