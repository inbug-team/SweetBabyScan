package main

import (
	"fmt"
	"net"
	"time"
)

func CheckICMP() bool {
	conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 3*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return false
	}
	return true
}

func main() {
	fmt.Println(CheckICMP())
}
