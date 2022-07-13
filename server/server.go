package server

import (
	"encoding/binary"

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

// For Wrapped Handshake Messages A-OK
func ReadRec2() []byte {
	buf := make([]byte, 5)
	network.Conn.Read(buf)
	l := binary.BigEndian.Uint16(buf[3:])
	rest := make([]byte, l)
	network.Conn.Read(rest)
	fin := help.Concat(buf, rest)
	iv := krypto.NewIV(session.HSCounter.Recv, session.Sekret.SHIV) // TEST

	ret := krypto.Decrypt(session.Sekret.SHK, iv, fin)
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
	iv := krypto.NewIV(session.ACounter.Recv, session.Sekret.SAIV)
	ret := krypto.Decrypt(session.Sekret.SAK, iv, fin)
	session.ACounter.Recv++
	return ret

}

func ReadServerHello() {
	session.NewSesh.SHBytes = ReadRec() // as it's unwrapped
	session.NewServerHello.Random = session.NewSesh.SHBytes[11:43]
	session.NewServerHello.Pubkey = session.NewSesh.SHBytes[len(session.NewSesh.SHBytes)-32:]

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
	iv := krypto.NewIV(session.ACounter.Recv, session.Sekret.SAIV)
	decrypt := krypto.Decrypt(session.Sekret.SAK, iv, fin) // maybe this is cert
	session.ACounter.Recv += 1
	return decrypt
}
