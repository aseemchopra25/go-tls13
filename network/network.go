package network

import (
	"log"
	"net"
)

func Connect() net.Conn {
	conn, err := net.Dial("tcp", "www.chopraaseem.com:443")
	if err != nil {
		log.Fatal(err)
	}
	return conn
}
