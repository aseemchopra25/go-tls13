package network

import (
	"fmt"
	"testing"
)

func TestNetwork(t *testing.T) {
	conn := Connect()
	fmt.Println(conn)

}
