package main

import (
	"fmt"
	"os"

	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/server"
	"github.com/aseemchopra25/go-toy-tls/session"
)

func main() {
	// 1. Create KeyPair for X25519
	krypto.GenerateKeyPair()

	// 2. Send Client Hello
	client.SendHello("chopraaseem.com")

	// 3. Read Server Hello
	server.ReadServerHello()

	// 4. Handshake Key Derivation
	krypto.HSKDerivation()

	// Skipping Server Change Cipher Spec 0x20

	session.NewSesh.SEEBytes = server.ReadRec2() // Confirmed Server Encrypted Extensions 	0

	session.NewSesh.SCBytes = server.ReadRec2() // Confirmed Server Certificate				1

	session.HSCounter.Recv += 1                  // Skipping Server Handshake Finished 2+1=	3
	session.NewSesh.SCVBytes = server.ReadRec2() // Confirmed Server Cert Verify			4

	session.HSCounter.Recv -= 3
	session.NewSesh.SHSBytes = server.ReadRec2() // Confirmed Server Handshake Finished		1

	// 6. Application Key Derivation
	krypto.AKDerivation()

	// ERROR ?
	server.ReadRec3()
	os.Exit(1) // remove this

	// 7. Send Client Change Cipher Spec
	client.SendChangeCipherSpec()

	// 8. Client Handshake Finished Key Derivation
	krypto.CHFKDerivation()

	// 9. Send Client Handshake Finished Message
	client.SendHandshakeFinished()

	// 10. Send Application Data
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", "chopraaseem.com")
	client.SendApplicationData([]byte(req))

	// 11. Read Application Data
	server.ReadApplicationData() // session ticket ignore/test
}
