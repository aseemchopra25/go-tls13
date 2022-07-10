package server

import (
	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/network"
	"github.com/aseemchopra25/go-toy-tls/session"
)

func ReadServerHello() {
	buf := make([]byte, 5)
	network.Conn.Read(buf)

	rest := make([]byte, int(buf[4]))
	network.Conn.Read(rest)
	session.NewSesh.SHBytes = help.Concat(buf, rest)
	session.NewServerHello.Random = session.NewSesh.SHBytes[11:43]
	session.NewServerHello.Pubkey = session.NewSesh.SHBytes[len(session.NewSesh.SHBytes)-32:]

	// fmt.Println("ServerHello Response:")
	// help.Hexparser(help.B2H(session.NewSesh.SHBytes)) // remove this
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
	session.NewSesh.SHSBytes = krypto.Decrypt(session.Sekret.SHK, session.Sekret.SHIV, encSHS)
	// fmt.Println(session.NewSesh.SHSBytes) // WORKS
}
