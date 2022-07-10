package krypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/sesh"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func GenerateKeyPair() {
	b := make([]byte, 32)
	rand.Read(b)
	sesh.NewKeyPair.PrivateKey = b
	sesh.NewKeyPair.PublicKey, _ = curve25519.X25519(b, curve25519.Basepoint)
}

// https://tls13.xargs.org/

// early_secret = HKDF-Extract(salt: 00, key: 00...)
// empty_hash = SHA384("")
// derived_secret = HKDF-Expand-Label(key: early_secret, label: "derived", ctx: empty_hash, len: 48)
// handshake_secret = HKDF-Extract(salt: derived_secret, key: shared_secret)
// client_secret = HKDF-Expand-Label(key: handshake_secret, label: "c hs traffic", ctx: hello_hash, len: 48)
// server_secret = HKDF-Expand-Label(key: handshake_secret, label: "s hs traffic", ctx: hello_hash, len: 48)
// client_handshake_key = HKDF-Expand-Label(key: client_secret, label: "key", ctx: "", len: 32)
// server_handshake_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
// client_handshake_iv = HKDF-Expand-Label(key: client_secret, label: "iv", ctx: "", len: 12)
// server_handshake_iv = HKDF-Expand-Label(key: server_secret, label: "iv", ctx: "", len: 12)

func KeyDerivation() {
	sesh.Sekret.SS, _ = curve25519.X25519(sesh.NewKeyPair.PrivateKey, sesh.NewServerHello.Pubkey)

	salt, secret := make([]byte, 32), make([]byte, 32)

	earlySecret := hkdf.Extract(sha256.New, secret, salt)
	derivedSecret := deriveSecret(earlySecret, "derived", []byte{})
	sesh.Sekret.HS = hkdf.Extract(sha256.New, sesh.Sekret.SS, derivedSecret)
	msgs := help.Concat(sesh.NewSesh.CHBytes[5:], sesh.NewSesh.SHBytes[5:])
	sesh.Sekret.CHS = deriveSecret(sesh.Sekret.HS, "c hs traffic", msgs)
	sesh.Sekret.SHS = deriveSecret(sesh.Sekret.HS, "s hs traffic", msgs)

	sesh.Sekret.CHK = ExpandLabel(sesh.Sekret.CHS, "key", []byte{}, 16) // test with 32
	sesh.Sekret.CHIV = ExpandLabel(sesh.Sekret.CHS, "iv", []byte{}, 12)

	sesh.Sekret.SHK = ExpandLabel(sesh.Sekret.SHS, "key", []byte{}, 16) // test with 32
	sesh.Sekret.SHIV = ExpandLabel(sesh.Sekret.SHS, "iv", []byte{}, 12) // WROTE CHS instead of SHS LOL

	// DEBUG
	// fmt.Println("Shared Secret		", sesh.Sekret.SS)
	// fmt.Println("Handshake Secret	", sesh.Sekret.HS)
	// fmt.Println("Client Handshake Secret	", sesh.Sekret.CHS)
	// fmt.Println("Server Handshake Secret	", sesh.Sekret.SHS)
	// fmt.Println("Client Handshake Key	", sesh.Sekret.CHK)
	// fmt.Println("Client Handshake IV	", sesh.Sekret.CHIV)
	// fmt.Println("Server Handshake Key	", sesh.Sekret.SHK)
	// fmt.Println("Server Handshake IV	", sesh.Sekret.SHIV)
}

// Derive Secret  https://github.com/golang/go/blob/c1a4e0fe014568501b194eb8b04309f54eee6b4c/src/crypto/tls/key_schedule.go#L54

func deriveSecret(secret []byte, label string, transcriptmsg []byte) []byte {
	hash := sha256.Sum256(transcriptmsg)
	return ExpandLabel(secret, label, hash[:], 32)
}

// HKDF-EXPAND-LABEL https://github.com/golang/go/blob/c1a4e0fe014568501b194eb8b04309f54eee6b4c/src/crypto/tls/key_schedule.go#L35

func ExpandLabel(secret []byte, label string, context []byte, length int) []byte {
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
	n, _ := hkdf.Expand(sha256.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if n != length {
		log.Panic("HKDF-Expand Failure")
	}
	return out
}

func Decrypt(key, iv, wrapper []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	extra, cipher := wrapper[:5], wrapper[5:]
	// fmt.Println(extra, cipher)
	plain, err := aesgcm.Open(nil, iv, cipher, extra)
	if err != nil {
		panic(err.Error()) // THROWN UP
	}

	return plain

}
