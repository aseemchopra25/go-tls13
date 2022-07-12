package server

import (
	"encoding/binary"
	"fmt"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/krypto"
	"github.com/aseemchopra25/go-toy-tls/network"
	"github.com/aseemchopra25/go-toy-tls/session"
)

// For Unwrapped Records

func ReadRec() []byte {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)
	return fin

}

// For Wrapped Handshake Messages
func ReadRec2() []byte {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)
	fmt.Println("")
	fmt.Println("-----------ENCRYPTED RECORD-----------")
	fmt.Println(fin) // could change to HEX if needed help.B2H
	fmt.Println("")
	fmt.Println("///////////////////////DECRYPTED RECORD///////////////////////")
	fmt.Println("HSCOUNTER RECV")
	fmt.Println(session.HSCounter.Recv)

	iv := krypto.NewIV(session.HSCounter.Recv, session.Sekret.SHIV) // TEST

	ret := krypto.Decrypt(session.Sekret.SHK, iv, fin)
	fmt.Println(help.B2H(ret))
	session.HSCounter.Recv++
	return ret

}

func ReadRec3() []byte {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)

	fmt.Println("")
	fmt.Println("----------------------ENCRYPTED RECORD---------------------------")
	fmt.Println(fin) // could change to HEX if needed help.B2H
	fmt.Println("")
	fmt.Println("///////////////////////DECRYPTED RECORD///////////////////////")
	fmt.Println("")

	iv := krypto.NewIV(session.ACounter.Recv, session.Sekret.SAIV)
	ret := krypto.Decrypt(session.Sekret.SAK, iv, fin)
	fmt.Println(help.B2H(ret))
	session.ACounter.Recv++
	return ret

}

func ReadServerHello() {
	session.NewSesh.SHBytes = ReadRec() // as it's unwrapped
	session.NewServerHello.Random = session.NewSesh.SHBytes[11:43]
	session.NewServerHello.Pubkey = session.NewSesh.SHBytes[len(session.NewSesh.SHBytes)-32:]

}

func ReadApplicationData() []byte {
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
	iv[11] ^= session.HSCounter.Recv
	decrypt := krypto.Decrypt(session.Sekret.SAK, iv, fin) // maybe this is cert
	session.HSCounter.Recv += 1
	fmt.Println(string(decrypt))
	return decrypt
}
