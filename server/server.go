package server

import (
	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/network"
	"github.com/aseemchopra25/go-toy-tls/sesh"
)

func ReadServerHello() {
	buf := make([]byte, 5)
	network.Conn.Read(buf)

	rest := make([]byte, int(buf[4]))
	network.Conn.Read(rest)
	sesh.NewSesh.SHBytes = help.Concat(buf, rest)
	sesh.NewServerHello.Random = sesh.NewSesh.SHBytes[11:43]
	sesh.NewServerHello.Pubkey = sesh.NewSesh.SHBytes[len(sesh.NewSesh.SHBytes)-32:]

	// fmt.Println("ServerHello Response:")
	// help.Hexparser(help.B2H(sesh.NewSesh.SHBytes)) // remove this
	// fmt.Println("ServerHello 32 Byte Random Extracted:")
	// help.Hexparser(help.B2H(NewServerHello.Random))
	// fmt.Println("")
	// fmt.Println("")
	// fmt.Println("ServerHello 32 Byte PubKey Extracted:")
	// help.Hexparser(help.B2H(NewServerHello.Pubkey))

}

func ReadServerHandshake() {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	rest := make([]byte, int(buf[4]))
	network.Conn.Read(rest)
	encSHS := help.Concat(buf, rest)
	// fmt.Println(encSHS)
	sesh.NewSesh.SHSBytes = krypto.Decrypt(sesh.Sekret.SHK, sesh.Sekret.SHIV, encSHS)
	// fmt.Println(sesh.NewSesh.SHSBytes) // WORKS
}
