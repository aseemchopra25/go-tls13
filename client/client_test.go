package client

import (
	"fmt"
	"testing"

	"github.com/aseemchopra25/go-toy-tls/help"
	"github.com/aseemchopra25/go-toy-tls/krypto"
)

// write function to convert byte to hex
// v := reflect.ValueOf(Ch)
// values := make([]interface{}, v.NumField())
// for i := 0; i < v.NumField(); i++ {
// 	values[i] = v.Field(i).Interface()
// 	fmt.Println(values[i])
// }

func TestClientHello(t *testing.T) {
	krypto.GenerateKeyPair()
	SendHello("test.com")
	// test Record Header
	fmt.Println("Record:", help.B2H(Ch.Rh))
	fmt.Println("Handshake:", help.B2H(Ch.Hh))
	fmt.Println("Client Version:", help.B2H(Ch.Cv))
	fmt.Println("Client Random:", help.B2H(Ch.Cr))
	fmt.Println("SessionID: ", help.B2H(Ch.Sid))
	fmt.Println("CipherSuites: ", help.B2H(Ch.Cs))
	fmt.Println("Compression Methods", help.B2H(Ch.Cm))
	// ---
	fmt.Println("Extension Length: ", help.B2H(Ch.El))
	fmt.Println("Server Name: ", help.B2H(Ch.Sn))
	fmt.Println("Supported Groups", help.B2H(Ch.Sg))
	fmt.Println("Signature Algorithms", help.B2H(Ch.Sa))
	fmt.Println("Supported Versions", help.B2H(Ch.Sv))
	fmt.Println("PreSharedKey: ", help.B2H(Ch.Psk))
	fmt.Println("Key Share", help.B2H(Ch.Ks))

}
