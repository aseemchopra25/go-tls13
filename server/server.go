package server

import (
	"fmt"
	"log"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/network"
)

type ServerHello struct {
	Random []byte
	Pubkey []byte
}

var NewServerHello ServerHello

func ReadServerHello() {
	buf := make([]byte, 5)
	x, err := network.Conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	if x != 5 {
		fmt.Println("Unable to read 20 bytes")
	}

	rest := make([]byte, int(buf[4]))
	network.Conn.Read(rest)
	serverHello := help.Concat(buf, rest) // read random and pubkey
	NewServerHello.Random = serverHello[11:43]
	NewServerHello.Pubkey = serverHello[len(serverHello)-32:]

	// Checking Values

	// fmt.Println("ServerHello Response:")
	// help.Hexparser(help.B2H(serverHello)) // remove this
	// fmt.Println("")
	// fmt.Println("")
	// fmt.Println("ServerHello 32 Byte Random Extracted:")
	// help.Hexparser(help.B2H(NewServerHello.Random))
	// fmt.Println("")
	// fmt.Println("")
	// fmt.Println("ServerHello 32 Byte PubKey Extracted:")
	// help.Hexparser(help.B2H(NewServerHello.Pubkey))
}
