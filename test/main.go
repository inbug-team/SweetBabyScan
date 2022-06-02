package main

import (
	"fmt"
	"os"
)

func main() {
	path := "./1.txt"
	if err := os.Remove(path); err != nil {
		fmt.Println(err)
	}
}
