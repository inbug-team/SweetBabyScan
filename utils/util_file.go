package utils

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
)

// 从字符串读取
func ReadLines(content string) (lines []string, err error) {
	br := bufio.NewReader(strings.NewReader(content))

	lines = make([]string, 0)
	for lineEnd := true; ; {
		lineBytes, isPrefix, err1 := br.ReadLine()
		if err1 != nil {
			if err1 != io.EOF {
				err = err1
			}
			break
		}

		line := string(lineBytes)
		if lineEnd == false {
			lines[len(lines)-1] += line

		} else {
			lines = append(lines, line)
			lineEnd = !isPrefix
		}
	}

	return
}

// 从文件读取
func ReadLinesFormFile(path string) (lines []string, err error) {
	file, _ := os.OpenFile(path, os.O_RDONLY, 0666)
	defer file.Close()

	br := bufio.NewReader(file)

	lines = make([]string, 0)
	for lineEnd := true; ; {
		lineBytes, isPrefix, err1 := br.ReadLine()
		if err1 != nil {
			if err1 != io.EOF {
				err = err1
			}
			break
		}

		line := string(lineBytes)
		if lineEnd == false {
			lines[len(lines)-1] += line

		} else {
			lines = append(lines, line)
			lineEnd = !isPrefix
		}
	}

	return
}

// 路径存在
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// 写入文件
func WriteContent(content, filename string) {
	var data = []byte(content)
	err := ioutil.WriteFile(fmt.Sprintf("./static/%s", filename), data, 0666)
	if err != nil {
		return
	}
}

func WriteByte(content []byte, filename string) {
	err := ioutil.WriteFile(fmt.Sprintf("./static/%s", filename), content, 0666)
	if err != nil {
		return
	}
}

// 写入csv
func WriteCsv(content [][]string, filename string) {
	f, err := os.Create(fmt.Sprintf("./static/%s", filename))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer f.Close()

	// 写入一个UTF-8 BOM
	f.WriteString("\xEF\xBB\xBF")

	//创建一个新的写入文件流
	w := csv.NewWriter(f)
	w.WriteAll(content)
	w.Flush()
}
