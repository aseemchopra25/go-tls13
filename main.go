package main

import (
	"fmt"

	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/server"
	"github.com/aseemchopra25/go-toy-tls/session"
)

func main() {
	// 1. Create KeyPair for X25519 A-OK
	krypto.GenerateKeyPair()

	// 2. Send Client Hello A-OK
	fmt.Printf("\nSending Client Hello\n")
	client.SendHello("vouch.io")
	fmt.Println(session.NewSesh.CHBytes)

	// 3. Read Server Hello A-OK
	fmt.Printf("\nREADING SERVER HELLO:\n")
	server.ReadServerHello()
	fmt.Println(session.NewSesh.SHBytes)

	// 4. Handshake Key Derivation A-OK
	krypto.HSKDerivation()
	krypto.PrintHSKeys()

	// 5. Server Change Cipher Spec
	fmt.Printf("\nSERVER CHANGE CIPHER SPEC EXTENSIONS:\n")
	session.NewSesh.SCCBytes = server.ReadRec() // Confirmed Server Encrypted Extensions

	// 6. Read Server Related Stuff A-OK
	fmt.Printf("\nSERVER ENCRYPTED EXTENSIONS:\n")
	session.NewSesh.SEEBytes = server.ReadRec2() // Confirmed Server Encrypted Extensions
	fmt.Printf("\nSERVER CERT\n")
	session.NewSesh.SCBytes = server.ReadRec2() // Confirmed Server Certificate
	fmt.Printf("\nSERVER CERT VERIFY\n")
	session.NewSesh.SCVBytes = server.ReadRec2() // Confirmed Server Cert Verify
	fmt.Printf("\nSERVER HANDSHAKE FINITO\n")
	session.NewSesh.SHSBytes = server.ReadRec2() // Confirmed Server Handshake Finished

	// ------------------------NEED CHECKINGS-------------------------------------
	// 6. Send Client Change Cipher Spec
	fmt.Printf("\nSENDING CLIENT CHANGE CIPHER SPEC\n")
	client.SendChangeCipherSpec()

	// 7. Client/Server Handshake Finished Key Derivation
	krypto.CHFKDerivation()

	// 8. Send Client Handshake Finished Message
	fmt.Printf("\nSENDING CLIENT HANDSHAKE FINISHED\n")
	client.SendHandshakeFinished()

	// 9. Application Key Derivation
	fmt.Printf("\nDERIVING APPLICATION KEYS\n")
	krypto.AKDerivation()

	// 10. Send Application Data
	// req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", "vouch.io/")
	req := "GET / HTTP/1.1\r\nHost: vouch.io\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)\r\n Chrome/92.0.4515.159 Safari/537.36\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"
	client.SendApplicationData([]byte(req))
	fmt.Printf("\nAPPLICATION DATA SENT!\n")
	fmt.Printf("\nREADING SESSION TICKET\n")
	server.ReadRec3() // Server New Session Ticket (SAIV/SAK)
	server.ReadRec3() // Server New Session Ticket (SAIV/SAK)

	fmt.Println("READING APPLICATION DATA")
	// 11. Read Application Data
	server.ReadAppData()
}
