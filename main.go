package main

import (
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

	// No Server Change Cipher Spec 0x20 seems to be seen here
	server.ReadRec2() // Confirmed Server Encrypted Extensions
	server.ReadRec2() // Confirmed Server Certificate
	// something was skipped here (which we didn't receive)
	session.HSCounter.Recv += 1
	server.ReadRec2()           // Confirmed Server Cert Verify
	session.HSCounter.Recv -= 3 // Confirmed Server Handshake Finished

	server.ReadRec2() // ? Server Handshake Finished
	os.Exit(1)        // remove this

	server.ReadRec2() //

	// // 5. Read Server Handshake
	// server.ReadServerHandshake()

	// // 6. Application Key Derivation
	// krypto.AKDerivation()

	// // 7. Send Client Change Cipher Spec
	// client.SendChangeCipherSpec()

	// // 8. Client Handshake Finished Key Derivation
	// krypto.CHFKDerivation()

	// // 9. Send Client Handshake Finished Message
	// client.SendHandshakeFinished()

	// // 10. Send Application Data
	// req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", "chopraaseem.com")
	// client.SendApplicationData([]byte(req))

	// // 11. Read Application Data
	// server.ReadApplicationData() // session ticket ignore/test
}
