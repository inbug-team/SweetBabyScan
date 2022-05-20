package utils

import (
	"fmt"
)

func PrintErr(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func PanicErr(err error) {
	if err != nil {
		panic(err)
	}
}
