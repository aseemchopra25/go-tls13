package server

import (
	"fmt"
	"testing"
)

func TestServer(t *testing.T) {
	f := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	fmt.Println(f[:2])
	fmt.Println(f[len(f)-3:])
}
