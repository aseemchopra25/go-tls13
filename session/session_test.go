package session

import (
	"fmt"
	"testing"
)

func TestSesh(t *testing.T) {

	fmt.Println(NewSesh.SHSBytes)
	fmt.Println(NewSesh.CHBytes)
	fmt.Println(NewSesh.SHBytes)
	fmt.Println(NewCounter.Recv)
	fmt.Println(NewCounter.Sent)
	fmt.Println(string([]byte{48, 13, 10, 13, 10, 23, 23, 232, 32, 3, 23, 232}))
}
