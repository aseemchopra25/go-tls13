package client

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/keypair"
	"github.com/aseemchopra25/go-toy-tls/network"
)

// 1. Client random
// 2. List of cipher suites that the client supports
// 3. List of public keys
// 4. Protocol version that client can support

type ClientHello struct {
	Rh  []byte
	Hh  []byte
	Cv  []byte
	Cr  []byte
	Sid []byte
	Cs  []byte
	Cm  []byte
	El  []byte
	//----extensions
	Sn  []byte
	Sg  []byte
	Sa  []byte
	Sv  []byte
	Psk []byte
	Ks  []byte
}

var Ch ClientHello

func CreateHello(name string) []byte {

	// Handshake Header
	Ch.Hh = []byte{0x01, 0x00}

	// Client Version DONE
	Ch.Cv = []byte{0x03, 0x03}

	// Client Random
	x := make([]byte, 32)
	rand.Read(x)
	Ch.Cr = x

	// Session ID (None)
	Ch.Sid = []byte{0x00}

	// Cipher Suites - TLS_AES_128_GCM_SHA256
	Ch.Cs = []byte{0x00, 0x02, 0x13, 0x01}

	// Compression Methods
	Ch.Cm = []byte{0x01, 0x00}

	// Extension - Server Name
	sb := []byte(name)
	l1 := len(sb)
	l1b := help.I2B(uint16(l1))
	dns := []byte{0x00}
	l2 := l1 + 3
	l2b := help.I2B(uint16(l2))
	l3 := l2 + 2
	l3b := help.I2B(uint16(l3))
	Ch.Sn = help.Concat([]byte{0x00, 0x00}, l3b, l2b, dns, l1b, sb)

	// Extension - Supported Groups
	Ch.Sg = []byte{0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d}

	// Extension - Signature Algorithms
	Ch.Sa = []byte{0x00, 0x0d, 0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01}

	// Extension - Supported Versions
	Ch.Sv = []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}

	// Extension - PSK Key ExChange
	Ch.Psk = []byte{0x00, 0x2d, 0x00, 0x02, 0x01, 0x01}

	// Extension - Key Share
	pub := keypair.NewKeyPair.PublicKey
	Ch.Ks = help.Concat([]byte{0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20}, pub)

	// Extension Length
	Ch.El = help.I2B(uint16(len(help.Concat(Ch.Sn, Ch.Sg, Ch.Sa, Ch.Sv, Ch.Psk, Ch.Ks))))

	// HANDSHAKE LENGTH len1
	len1 := len(help.Concat(Ch.Cv, Ch.Cr, Ch.Sid, Ch.Cs, Ch.Cm, Ch.El, Ch.Sn, Ch.Sg, Ch.Sa, Ch.Sv, Ch.Psk, Ch.Ks))
	Ch.Hh = append(Ch.Hh[:], help.I2B(uint16(len1))[:]...)

	// Record Header
	Ch.Rh = []byte{0x16, 0x03, 0x01}
	len2 := help.I2B(uint16(len1 + 4))
	Ch.Rh = append(Ch.Rh[:], len2[:]...)

	lol := help.Concat(Ch.Rh, Ch.Hh, Ch.Cv, Ch.Cr, Ch.Sid, Ch.Cs, Ch.Cm, Ch.El, Ch.Sn, Ch.Sg, Ch.Sa, Ch.Sv, Ch.Psk, Ch.Ks)
	return lol
}

func SendHello(name string) {
	// 3. Connect
	msg := CreateHello(name)
	// 3. Connect
	network.Conn = network.Connect()
	// 4. Send ClientHello
	n, err := network.Conn.Write(msg)
	if err != nil {
		log.Fatal(err)
	}
	if n != len(msg) {
		fmt.Println("not send completely")
	}

}
