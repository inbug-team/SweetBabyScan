package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func generatePwd() (passwords []string) {
	var pwdPrefix string
	var pwdCenter string
	var pwdSuffix string
	fmt.Println("Password Generator 弱口令生成器，多个以空格隔开")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("[password prefix] > ")
	pwdPrefix, _ = reader.ReadString('\n')
	fmt.Print("[password center] > ")
	pwdCenter, _ = reader.ReadString('\n')
	fmt.Print("[password suffix] > ")
	pwdSuffix, _ = reader.ReadString('\n')

	_pwdPrefix := strings.Split(strings.TrimSpace(pwdPrefix), " ")
	_pwdCenter := strings.Split(strings.TrimSpace(pwdCenter), " ")
	_pwdSuffix := strings.Split(strings.TrimSpace(pwdSuffix), " ")
	if len(_pwdPrefix) == 0 {
		_pwdPrefix = []string{""}
	}
	if len(_pwdCenter) == 0 {
		_pwdCenter = []string{""}
	}
	if len(_pwdSuffix) == 0 {
		_pwdSuffix = []string{""}
	}

	for _, v1 := range _pwdPrefix {
		for _, v2 := range _pwdCenter {
			for _, v3 := range _pwdSuffix {
				passwords = append(passwords, fmt.Sprintf(`%s%s%s`, v1, v2, v3))
			}
		}
	}
	fmt.Println(fmt.Sprintf("[password result] %d record:", len(passwords)))
	fmt.Println(strings.Join(passwords, " "))
	return
}

func main() {
	generatePwd()
}
