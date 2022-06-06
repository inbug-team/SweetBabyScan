package main

import "fmt"

func main() {

	a := map[string]string{"a": "1", "b": "2"}
	for k := range a {
		fmt.Println(k)
	}

	arr := []string{"1", "2"}
	arr = append(arr, []string{"3", "4"}...)
	fmt.Println(arr)
}
