package plugin_scan_net

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/utils"
	"net"
	"strings"
	"time"
)

var (
	bufferV1, _ = hex.DecodeString("05000b03100000004800000001000000b810b810000000000100000000000100c4fefc9960521b10bbcb00aa0021347a00000000045d888aeb1cc9119fe808002b10486002000000")
	bufferV2, _ = hex.DecodeString("050000031000000018000000010000000000000000000500")
	bufferV3, _ = hex.DecodeString("0900ffff0000")
)

func ScanNet(ip string, timeOut uint) (netData []string, err error) {
	netData, err = scanNet(ip, timeOut)
	return netData, err
}

func scanNet(ip string, timeOut uint) (netData []string, err error) {
	// 连接
	timeout := time.Duration(timeOut) * time.Second
	realHost := fmt.Sprintf("%s:%d", ip, 135)
	conn, err := net.DialTimeout("tcp", realHost, timeout)
	if err != nil {
		return netData, err
	}
	defer func() {
		err := conn.Close()
		utils.PrintErr(err)
	}()

	// 写超时
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return netData, err
	}
	_, err = conn.Write(bufferV1)
	if err != nil {
		return netData, err
	}

	// 读超时
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return netData, err
	}
	reply := make([]byte, 4096)
	_, err = conn.Read(reply)
	if err != nil {
		return netData, err
	}

	// 写超时
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return netData, err
	}
	_, err = conn.Write(bufferV2)
	if err != nil {
		return netData, err
	}

	// 读超时
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return netData, err
	}
	if n, err := conn.Read(reply); err != nil || n < 42 {
		return netData, err
	}

	text := reply[42:]
	flag := true
	for i := 0; i < len(text)-5; i++ {
		if bytes.Equal(text[i:i+6], bufferV3) {
			text = text[:i-4]
			flag = false
			break
		}
	}
	if flag {
		return netData, err
	}
	netData, err = read(text, ip)
	return netData, err
}

func read(text []byte, ip string) (netData []string, err error) {
	encodedStr := hex.EncodeToString(text)
	hostNames := strings.Replace(encodedStr, "0700", "", -1)
	hostname := strings.Split(hostNames, "000000")
	result := "网卡信息：\n[*]" + ip

	for i := 0; i < len(hostname); i++ {
		hostname[i] = strings.Replace(hostname[i], "00", "", -1)
		host, err := hex.DecodeString(hostname[i])
		if err != nil {
			return netData, err
		}
		result += "\n   [->]" + string(host)
		netData = append(netData, string(host))
	}
	//fmt.Println(result)
	return netData, nil
}
