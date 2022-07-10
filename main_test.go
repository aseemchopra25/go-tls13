package main

import (
	"fmt"
	"testing"
)

func TestMain(t *testing.T) {
	a := []byte{1, 2, 3, 4, 6}
	fmt.Println(a[:len(a)-1])
}
