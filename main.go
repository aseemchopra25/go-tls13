package main

import (
	"encoding/binary"
	"fmt"

	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/network"
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

	session.NewSesh.SEEBytes = server.ReadRec2() // Confirmed Server Encrypted Extensions

	session.NewSesh.SCBytes = server.ReadRec2() // Confirmed Server Certificate

	session.NewSesh.SCVBytes = server.ReadRec2() // Confirmed Server Cert Verify

	session.NewSesh.SHSBytes = server.ReadRec2() // Confirmed Server Handshake Finished

	// 6. Application Key Derivation
	krypto.AKDerivation()

	server.ReadRec3() // Server New Session Ticket (SAIV/SAK)

	// 7. Send Client Change Cipher Spec SKIP THIS
	// client.SendChangeCipherSpec()

	// 8. Client Handshake Finished Key Derivation
	krypto.CHFKDerivation()

	// 9. Send Client Handshake Finished Message
	client.SendHandshakeFinished()
	fmt.Println("SENT CLIENT HANDSHAKE FINISHED!")

	// 10. Send Application Data
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", "chopraaseem.com")
	client.SendApplicationData([]byte(req))

	fmt.Println("APP DATA SENT!....Waiting for response")

	buf := make([]byte, 5)
	network.Conn.Read(buf)
	fmt.Println(buf)
	// fmt.Println(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, int(l))
	network.Conn.Read(rest)
	fmt.Println(rest)

	server.ReadAppData()
	// 11. Read Application Data
	server.ReadApplicationData() // session ticket ignore/test
}
