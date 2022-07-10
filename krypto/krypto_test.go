package krypto

import (
	"crypto/sha512"
	"fmt"
	"log"
	"testing"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/session"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

// func TestDecrypt(t *testing.T) {

// 	// wrapper := hex.DecodeString()

// 	key := help.HexToByte("9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f")
// 	iv := help.HexToByte("9563bc8b590f671f488d2da3")
// 	wrapper := help.HexToByte("17 03 03 00 17 6b e0 2f 9d a7 c2 dc 9d de f5 6f 24 68 b9 0a df a2 51 01 ab 03 44 ae")
// 	b := Decrypt(key, iv, wrapper)

// 	fmt.Println(help.B2H(b)) // works

// }

func TestKDF(t *testing.T) {
	ss := help.HexToByte("df4a291baa1eb7cfa6934b29b474baad2697e29f1f920dcc77c8a0a088447624")
	hh := help.HexToByte("e05f64fcd082bdb0dce473adf669c2769f257a1c75a51b7887468b5e0e7a7de4f4d34555112077f16e079019d5a845bd")
	hs := help.HexToByte("bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299")
	salt, secret := make([]byte, 48), make([]byte, 48)
	earlySecret := hkdf.Extract(sha512.New384, secret, salt)
	derivedSecret := deriveSecret2(earlySecret, "derived", []byte{})
	session.Sekret.HS = hkdf.Extract(sha512.New384, ss, derivedSecret)
	fmt.Println(help.B2H((session.Sekret.HS)))
	fmt.Println(help.B2H((hs)))

	if (session.Sekret.HS)[10] != hs[10] {
		log.Fatal("LOL")
	}
	session.Sekret.CHS = deriveSecret(hs, "c hs traffic", hh)
	session.Sekret.SHS = deriveSecret(hs, "s hs traffic", hh)

	session.Sekret.CHK = ExpandLabel2(session.Sekret.CHS, "key", []byte{}, 32)
	session.Sekret.CHIV = ExpandLabel2(session.Sekret.CHS, "iv", []byte{}, 12)

	session.Sekret.SHK = ExpandLabel2(session.Sekret.SHS, "key", []byte{}, 32)
	session.Sekret.SHIV = ExpandLabel2(session.Sekret.CHS, "iv", []byte{}, 12)

}

func deriveSecret2(secret []byte, label string, transcriptmsg []byte) []byte {
	hash := sha512.Sum384(transcriptmsg)
	return ExpandLabel2(secret, label, hash[:], 48)
}

func ExpandLabel2(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, _ := hkdf.Expand(sha512.New384, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if n != length {
		log.Panic("HKDF-Expand Failure")
	}
	return out
}
