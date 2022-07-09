package main

import (
	"fmt"
	"io"
	"log"

	"github.com/aseemchopra25/go-toy-tls/client"
	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/keypair"
	"github.com/aseemchopra25/go-toy-tls/network"
)

func main() {
	var Conn io.ReadWriteCloser
	// 1. Create KeyPair for X25519
	keypair.Generate()
	// 2. Generate Client Hello
	msg := client.Hello("www.chopraaseem.com")
	// 3. Connect
	Conn = network.Connect()
	// 4. Send ClientHello
	n, err := Conn.Write(msg)
	if err != nil {
		log.Fatal(err)
	}
	if n != len(msg) {
		fmt.Println("not send completely")
	}
	buf := make([]byte, 20)
	x, err := Conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(help.B2H(buf))
	if x != 20 {
		fmt.Println("Unable to read 20 bytes")
	}
}
