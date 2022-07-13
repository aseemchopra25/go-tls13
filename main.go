package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/server"
	"github.com/aseemchopra25/go-toy-tls/session"
)

func main() {
	// 0. Starting Execution Timer:
	start := time.Now()

	// 1. Create KeyPair for X25519 A-OK
	krypto.GenerateKeyPair()

	// 2. Send Client Hello A-OK
	client.SendHello("vouch.io")

	// 3. Read Server Hello A-OK
	server.ReadServerHello()

	// 4. Handshake Key Derivation A-OK
	krypto.HSKDerivation()
	// krypto.PrintHSKeys()

	// 5. Server Change Cipher Spec
	session.NewSesh.SCCBytes = server.ReadRec() // Confirmed Server Encrypted Extensions

	// 6. Read Server Related Stuff A-OK
	session.NewSesh.SEEBytes = server.ReadRec2() // Confirmed Server Encrypted Extensions
	session.NewSesh.SCBytes = server.ReadRec2()  // Confirmed Server Certificate
	session.NewSesh.SCVBytes = server.ReadRec2() // Confirmed Server Cert Verify
	session.NewSesh.SHSBytes = server.ReadRec2() // Confirmed Server Handshake Finished

	// ------------------------NEED CHECKINGS-------------------------------------
	// 6. Send Client Change Cipher Spec
	client.SendChangeCipherSpec()

	// 7. Client/Server Handshake Finished Key Derivation
	krypto.CHFKDerivation()

	// 8. Send Client Handshake Finished Message
	client.SendHandshakeFinished()

	// 9. Application Key Derivation
	krypto.AKDerivation()

	// 10. Send Application Data
	// req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", "vouch.io/")

	// ALLOWS GZIP ENCODING
	req := "GET / HTTP/1.1\r\nHost: vouch.io\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)\r\n Chrome/92.0.4515.159 Safari/537.36\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"

	// DISALLOW GZIP ENCODING
	// req := "GET / HTTP/1.1\r\nHost: vouch.io\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)\r\n Chrome/92.0.4515.159 Safari/537.36\r\nAccept-Language: en-GB,en-US;q=0.9,en;q=0.8\r\nConnection: close\r\n\r\n"
	client.SendApplicationData([]byte(req))
	server.ReadRec3() // Server New Session Ticket (SAIV/SAK)
	server.ReadRec3() // Server New Session Ticket (SAIV/SAK)

	// 11. Read Application Data
	server.ReadAppData()
	x := server.ReadAppData()
	reader, _ := gzip.NewReader(bytes.NewReader(x))
	_, _ = io.Copy(os.Stdout, reader)

	// Time of Execution
	fmt.Println("")
	fmt.Println(time.Since(start))

}
