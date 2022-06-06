package main

import "fmt"

func main() {

	a := map[string]string{"a": "1", "b": "2"}
	for k := range a {
		fmt.Println(k)
	}

}
