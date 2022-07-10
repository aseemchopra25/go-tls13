package server

import (
	"encoding/binary"
	"fmt"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/network"
	"github.com/aseemchopra25/go-toy-tls/session"
)

func ReadServerHello() {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	// fmt.Println(buf)
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
	// fmt.Println(buf)
	rest := make([]byte, int(buf[4]))
	network.Conn.Read(rest)
	rec := help.Concat(buf, rest)
	// fmt.Println(encSHS)
	session.NewSesh.SHSBytes = krypto.Decrypt(session.Sekret.SHK, session.Sekret.SHIV, rec)
	// fmt.Println(session.NewSesh.SHSBytes) // WORKS
}

func ReadApplicationData() []byte {
	GetData() // Ignore Session Ticket
	var resp []byte
	// for {
	// 	plain := GetData() // TLS in chunks
	// 	if string(plain) == string([]byte{48, 13, 10, 13, 10, 23}) {
	// 		break
	// 	}
	// 	resp = append(resp, plain...)
	// }
	// fmt.Println(resp)
	return resp
}

func GetData() []byte {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	// fmt.Println(buf[3:])
	// fmt.Println(help.B2I(buf[3:]))
	// fmt.Println("----------------------")
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	rec := help.Concat(buf, rest)
	// fmt.Println(rec)
	// fmt.Println(len(rec))
	iv := make([]byte, 12)
	copy(iv, session.Sekret.SAIV)
	iv[11] ^= session.NewCounter.Recv // this seems to be incorrect as I think the xor should be looped
	// some problem here
	fmt.Println("Session Application Key with Length", len(session.Sekret.SAK), session.Sekret.SAK)
	fmt.Println("Session Application IV with Length", len(session.Sekret.SAIV), session.Sekret.SAIV)
	decrypt := krypto.Decrypt(session.Sekret.SAK, iv, rec)
	session.NewCounter.Recv += 1
	return decrypt
}
