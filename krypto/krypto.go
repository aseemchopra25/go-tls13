package krypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/session"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func GenerateKeyPair() {
	b := make([]byte, 32)
	rand.Read(b)
	session.NewKeyPair.PrivateKey = b
	session.NewKeyPair.PublicKey, _ = curve25519.X25519(b, curve25519.Basepoint)
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

// THIS IS FULLY FUNCTIONAL
func HSKDerivation() {
	session.Sekret.SS, _ = curve25519.X25519(session.NewKeyPair.PrivateKey, session.NewServerHello.Pubkey)

	salt, secret := make([]byte, 32), make([]byte, 32)

	earlySecret := hkdf.Extract(sha256.New, secret, salt)
	derivedSecret := deriveSecret(earlySecret, "derived", []byte{})
	session.Sekret.HS = hkdf.Extract(sha256.New, session.Sekret.SS, derivedSecret)
	msgs := help.Concat(session.NewSesh.CHBytes[5:], session.NewSesh.SHBytes[5:])
	session.Sekret.CHS = deriveSecret(session.Sekret.HS, "c hs traffic", msgs)
	session.Sekret.SHS = deriveSecret(session.Sekret.HS, "s hs traffic", msgs)

	session.Sekret.CHK = ExpandLabel(session.Sekret.CHS, "key", []byte{}, 16) // test with 32
	session.Sekret.CHIV = ExpandLabel(session.Sekret.CHS, "iv", []byte{}, 12)

	session.Sekret.SHK = ExpandLabel(session.Sekret.SHS, "key", []byte{}, 16) // test with 32
	session.Sekret.SHIV = ExpandLabel(session.Sekret.SHS, "iv", []byte{}, 12) // WROTE CHS instead of SHS LOL

	// DEBUG
	// fmt.Println("Shared Secret		", session.Sekret.SS)
	// fmt.Println("Handshake Secret	", session.Sekret.HS)
	// fmt.Println("Client Handshake Secret	", session.Sekret.CHS)
	// fmt.Println("Server Handshake Secret	", session.Sekret.SHS)
	// fmt.Println("Client Handshake Key	", session.Sekret.CHK)
	// fmt.Println("Client Handshake IV	", session.Sekret.CHIV)
	// fmt.Println("Server Handshake Key	", session.Sekret.SHK)
	// fmt.Println("Server Handshake IV	", session.Sekret.SHIV)
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

// PROBLEM

func Decrypt(key, iv, wrapper []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	extra, cipherx := wrapper[:5], wrapper[5:]
	// fmt.Println(extra, cipher)
	// fmt.Println("HERE")
	plain, err := aesgcm.Open(nil, iv, cipherx, extra)
	if err != nil {
		panic(err.Error()) // THROWN UP
	}

	return plain

}

func Encrypt(key, iv, plain, extra []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err.Error())
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	ciphertxt := aesgcm.Seal(nil, iv, plain, extra)
	return append(extra, ciphertxt...)
}

// https://tls13.xargs.org/
// empty_hash = SHA384("")
// derived_secret = HKDF-Expand-Label(key: handshake_secret, label: "derived", ctx: empty_hash, len: 48)
// master_secret = HKDF-Extract(salt: derived_secret, key: 00...)
// client_secret = HKDF-Expand-Label(key: master_secret, label: "c ap traffic", ctx: handshake_hash, len: 48)
// server_secret = HKDF-Expand-Label(key: master_secret, label: "s ap traffic", ctx: handshake_hash, len: 48)
// client_application_key = HKDF-Expand-Label(key: client_secret, label: "key", ctx: "", len: 32)
// server_application_key = HKDF-Expand-Label(key: server_secret, label: "key", ctx: "", len: 32)
// client_application_iv = HKDF-Expand-Label(key: client_secret, label: "iv", ctx: "", len: 12)
// server_application_iv = HKDF-Expand-Label(key: server_secret, label: "iv", ctx: "", len: 12)

// PROBLEM
func AKDerivation() {
	msgs := HHash()
	zeros := make([]byte, 32)
	derivedSecret := deriveSecret(session.Sekret.HS, "derived", []byte{})
	masterSecret := hkdf.Extract(sha256.New, zeros, derivedSecret)

	casecret := deriveSecret(masterSecret, "c ap traffic", msgs)

	session.Sekret.CAK = ExpandLabel(casecret, "key", []byte{}, 16)
	session.Sekret.CAIV = ExpandLabel(casecret, "iv", []byte{}, 12)

	sasecret := deriveSecret(masterSecret, "s ap traffic", msgs)

	session.Sekret.SAK = ExpandLabel(sasecret, "key", []byte{}, 16)
	session.Sekret.SAIV = ExpandLabel(sasecret, "iv", []byte{}, 12)
}

func HHash() []byte {

	// -1 on SHS because last byte is 0x16 tls1.3 disguised as tls 1.2

	msgs := help.Concat(
		session.NewSesh.CHBytes[5:], // unwrapped
		session.NewSesh.SHBytes[5:], // unwrapped
		session.NewSesh.SEEBytes[:len(session.NewSesh.SEEBytes)-1],
		session.NewSesh.SCBytes[:len(session.NewSesh.SCBytes)-1],
		session.NewSesh.SCVBytes[:len(session.NewSesh.SCVBytes)-1],
		session.NewSesh.SHSBytes[:len(session.NewSesh.SHSBytes)-1])
	return msgs
}

func CHFKDerivation() {
	session.Sekret.CHF = ExpandLabel(session.Sekret.CHS, "finished", []byte{}, 32)
	// fmt.Println("CLIENT HANDSHAKE FINISHED:", session.Sekret.CHF)
}

// https://github.com/syncsynchalt/tincan-tls/blob/51a1e468df0935fac156f7e7af6900cfa9cb389f/tls/conncrypt.go#L44

// func BuildIV(seq uint64, base []byte) []byte {
// 	result := make([]byte, len(base))
// 	copy(result, base)
// 	for i := 0; i < 8; i++ {
// 		result[len(result)-i-1] ^= byte(seq >> uint(8*i))
// 	}
// 	return result
// }
