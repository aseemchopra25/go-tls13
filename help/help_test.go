package help

import (
	"fmt"
	"testing"
)

func TestHelper(t *testing.T) {
	test := []byte{0x00, 0x7a}
	x := B2I(test)
	fmt.Println(x)
	fmt.Println(I2B(90))
}
