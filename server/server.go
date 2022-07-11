package server

import (
	"encoding/binary"
	"fmt"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/network"
	"github.com/aseemchopra25/go-toy-tls/session"
)

var flag int

func ReadRec() []byte {
	flag++
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)
	return fin

}
func ReadRec2() []byte {
	flag++
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)
	fmt.Println("----------------------PRINTING RECORD-------------------------------")
	fmt.Println(fin)
	return fin

}

func ReadServerHello() {
	session.NewSesh.SHBytes = ReadRec()
	session.NewServerHello.Random = session.NewSesh.SHBytes[11:43]
	session.NewServerHello.Pubkey = session.NewSesh.SHBytes[len(session.NewSesh.SHBytes)-32:]

}

func ReadServerHandshake() {
	fin := ReadRec()
	session.NewSesh.SHSBytes = krypto.Decrypt(session.Sekret.SHK, session.Sekret.SHIV, fin)
}

func ReadApplicationData() []byte {
	ReadRec2() // Ignore Session Ticket
	ReadRec2() // Ignore Session Ticket
	ReadRec2() // Ignore Session Ticket
	ReadRec2() // Ignore Session Ticket
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

// PROBLEM: Message Reading seems fine though
func ReadAppData() []byte {
	flag++
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	// fmt.Println(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, int(l))
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)
	fmt.Println("----------------------PRINTING RECORD-------------------------------")
	fmt.Println(fin)
	iv := make([]byte, 12)
	copy(iv, session.Sekret.SAIV)
	iv[11] ^= session.NewCounter.Recv
	decrypt := krypto.Decrypt(session.Sekret.SAK, iv, fin) // maybe this is cert
	session.NewCounter.Recv += 1
	fmt.Println(string(decrypt))
	return decrypt
}
