package plugin_scan_net_bios

import (
	"bytes"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/utils"
	"net"
	"strconv"
	"strings"
	"time"
)

var (
	UniqueNames = map[string]string{
		"\x00": "Workstation Service",
		"\x03": "Messenger Service",
		"\x06": "RAS Server Service",
		"\x1F": "NetDDE Service",
		"\x20": "Server Service",
		"\x21": "RAS Client Service",
		"\xBE": "Network Monitor Agent",
		"\xBF": "Network Monitor Application",
		"\x1D": "Master Browser",
		"\x1B": "Domain Master Browser",
	}

	GroupNames = map[string]string{
		"\x00": "Domain Name",
		"\x1C": "Domain Controllers",
		"\x1E": "Browser Service Elections",
	}

	NetBIOSItemType = map[string]string{
		"\x01\x00": "NetBIOS computer name",
		"\x02\x00": "NetBIOS domain name",
		"\x03\x00": "DNS computer name",
		"\x04\x00": "DNS domain name",
		"\x05\x00": "DNS tree name",
		"\x07\x00": "Time stamp",
	}
)

type NBSName struct {
	unique    string
	group     string
	msg       string
	osVersion string
}

func ScanNetBIOS(ip string, port, timeOut uint) (result map[string]string, err error) {
	nbsName, err := NetBIOS1(ip, port, timeOut)
	if err != nil {
		return result, err
	}
	result = map[string]string{
		"type":       "NetBIOS",
		"port":       fmt.Sprintf(`%d`, port),
		"ip":         ip,
		"unique":     nbsName.unique,
		"group":      nbsName.group,
		"msg":        nbsName.msg,
		"os_version": nbsName.osVersion,
		"is_dc":      "否",
	}

	var msg, isDc string

	if strings.Contains(nbsName.msg, "Domain Controllers") {
		isDc = "[+]DC"
		result["is_dc"] = "是"
	}

	msg += fmt.Sprintf("[*] %-15s%-5s %s\\%-15s   %s", ip, isDc, nbsName.group, nbsName.unique, nbsName.osVersion)
	msg += "\n-------------------------------------------\n" + nbsName.msg
	if len(nbsName.group) > 0 || len(nbsName.unique) > 0 {
		//fmt.Println(msg)
	}
	return result, nil
}

func NetBIOS1(ip string, port, timeOut uint) (nbsName NBSName, err error) {
	// 连接
	nbsName, err = GetNBSName(ip, timeOut)
	var payload0 []byte
	if err == nil {
		name := netBiosEncode(nbsName.unique)
		payload0 = append(payload0, []byte("\x81\x00\x00D ")...)
		payload0 = append(payload0, name...)
		payload0 = append(payload0, []byte("\x00 EOENEBFACACACACACACACACACACACACA\x00")...)
	}
	realHost := fmt.Sprintf("%s:%d", ip, port)
	timeout := time.Duration(timeOut) * time.Second
	conn, err := net.DialTimeout("tcp", realHost, timeout)
	if err != nil {
		return
	}
	defer func() {
		err := conn.Close()
		utils.PrintErr(err)
	}()

	if port == 139 && len(payload0) > 0 {
		// 写超时
		err = conn.SetWriteDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}
		_, err1 := conn.Write(payload0)
		if err1 != nil {
			return
		}

		// 读超时
		err = conn.SetReadDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}
		_, err1 = readBytes(conn)
		if err1 != nil {
			return
		}
	}

	// 写超时
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	payload1 := []byte("\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00")
	payload2 := []byte("\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00")
	_, err = conn.Write(payload1)
	if err != nil {
		return
	}

	// 读超时
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	_, err = readBytes(conn)
	if err != nil {
		return
	}

	// 写超时
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	_, err = conn.Write(payload2)
	if err != nil {
		return
	}

	// 读超时
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	ret, err := readBytes(conn)
	if err != nil || len(ret) < 45 {
		return
	}

	num1, err := byteToInt(ret[43:44][0])
	if err != nil {
		return
	}
	num2, err := byteToInt(ret[44:45][0])
	if err != nil {
		return
	}
	length := num1 + num2*256
	if len(ret) < 48+length {
		return
	}
	osVersion := ret[47+length:]
	tmp1 := bytes.ReplaceAll(osVersion, []byte{0x00, 0x00}, []byte{124})
	tmp1 = bytes.ReplaceAll(tmp1, []byte{0x00}, []byte{})
	msg1 := string(tmp1[:len(tmp1)-1])
	nbsName.osVersion = msg1
	index1 := strings.Index(msg1, "|")
	if index1 > 0 {
		nbsName.osVersion = nbsName.osVersion[:index1]
	}
	nbsName.msg += "-------------------------------------------\n"
	nbsName.msg += msg1 + "\n"
	start := bytes.Index(ret, []byte("NTLMSSP"))
	if len(ret) < start+45 {
		return
	}
	num1, err = byteToInt(ret[start+40 : start+41][0])
	if err != nil {
		return
	}
	num2, err = byteToInt(ret[start+41 : start+42][0])
	if err != nil {
		return
	}
	length = num1 + num2*256
	num1, err = byteToInt(ret[start+44 : start+45][0])
	if err != nil {
		return
	}
	offset, err := byteToInt(ret[start+44 : start+45][0])
	if err != nil || len(ret) < start+offset+length {
		return
	}
	index := start + offset
	for index < start+offset+length {
		itemType := ret[index : index+2]
		num1, err = byteToInt(ret[index+2 : index+3][0])
		if err != nil {
			return
		}
		num2, err = byteToInt(ret[index+3 : index+4][0])
		if err != nil {
			return
		}
		itemLength := num1 + num2*256
		itemContent := bytes.ReplaceAll(ret[index+4:index+4+itemLength], []byte{0x00}, []byte{})
		index += 4 + itemLength
		if string(itemType) == "\x07\x00" {
			//Time stamp, 暂时不想处理
		} else if NetBIOSItemType[string(itemType)] != "" {
			nbsName.msg += fmt.Sprintf("%-22s: %s\n", NetBIOSItemType[string(itemType)], string(itemContent))
		} else if string(itemType) == "\x00\x00" {
			break
		} else {
			nbsName.msg += fmt.Sprintf("Unknown: %s\n", string(itemContent))
		}
	}
	return nbsName, err
}

func GetNBSName(ip string, timeOut uint) (nbsName NBSName, err error) {
	// 连接
	sendData1 := []byte{102, 102, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32, 67, 75, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 65, 0, 0, 33, 0, 1}
	realHost := fmt.Sprintf("%s:%v", ip, 137)
	timeout := time.Duration(timeOut) * time.Second
	conn, err := net.DialTimeout("udp", realHost, timeout)
	if err != nil {
		return
	}
	defer func() {
		err := conn.Close()
		utils.PrintErr(err)
	}()

	// 写超时
	err = conn.SetWriteDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	_, err = conn.Write(sendData1)
	if err != nil {
		return
	}

	// 读超时
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return
	}
	text, err := readBytes(conn)
	if err != nil {
		return
	}
	if len(text) < 57 {
		return nbsName, fmt.Errorf("no names available")
	}
	num, err := byteToInt(text[56:57][0])
	if err != nil {
		return
	}
	data := text[57:]
	var msg string
	for i := 0; i < num; i++ {
		if len(data) < 18*i+16 {
			break
		}
		name := string(data[18*i : 18*i+15])
		flagBit := data[18*i+15 : 18*i+16]
		if GroupNames[string(flagBit)] != "" && string(flagBit) != "\x00" {
			msg += fmt.Sprintf("%s G %s\n", name, GroupNames[string(flagBit)])
		} else if UniqueNames[string(flagBit)] != "" && string(flagBit) != "\x00" {
			msg += fmt.Sprintf("%s U %s\n", name, UniqueNames[string(flagBit)])
		} else if string(flagBit) == "\x00" || len(data) >= 18*i+18 {
			nameFlags := data[18*i+16 : 18*i+18][0]
			if nameFlags >= 128 {
				nbsName.group = strings.Replace(name, " ", "", -1)
				msg += fmt.Sprintf("%s G %s\n", name, GroupNames[string(flagBit)])
			} else {
				nbsName.unique = strings.Replace(name, " ", "", -1)
				msg += fmt.Sprintf("%s U %s\n", name, GroupNames[string(flagBit)])
			}
		} else {
			msg += fmt.Sprintf("%s \n", name)
		}
	}
	nbsName.msg += msg
	return
}

func readBytes(conn net.Conn) (result []byte, err error) {
	buf := make([]byte, 4096)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		result = append(result, buf[0:count]...)
		if count < 4096 {
			break
		}
	}
	return result, err
}

func byteToInt(text byte) (int, error) {
	num1 := fmt.Sprintf("%v", text)
	num, err := strconv.Atoi(num1)
	return num, err
}

func netBiosEncode(name string) (output []byte) {
	var names []int
	src := fmt.Sprintf("%-16s", name)
	for _, a := range src {
		charOrd := int(a)
		high4Bits := charOrd >> 4
		low4Bits := charOrd & 0x0f
		names = append(names, high4Bits, low4Bits)
	}
	for _, one := range names {
		out := one + 0x41
		output = append(output, byte(out))
	}
	return
}
