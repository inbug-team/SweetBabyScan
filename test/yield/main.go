package main

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/utils"
)

func main() {
	channel := utils.Yield(func(_channel chan interface{}) {
		for i := 1; i < 99999; i++ {
			_channel <- i
			<-_channel
		}
	})
	for val := range channel {
		fmt.Println(val)
		channel <- 0
	}
}
