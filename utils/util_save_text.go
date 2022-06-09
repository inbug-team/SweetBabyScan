package utils

import (
	"os"
)

func SaveText(filename string, data []string) {
	f, _ := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_RDWR, os.ModeAppend|os.ModePerm)

	defer f.Close()

	for _, item := range data {
		f.WriteString(item)
	}
}
