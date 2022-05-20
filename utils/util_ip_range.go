package utils

import (
	"bytes"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync"
)

/*根据网络网段，获取该段所有IP—单例模式*/
type IpRange struct{}

var (
	_IpRange *IpRange
	SyncOnce sync.Once
)

func NewIpRangeLib() *IpRange {
	SyncOnce.Do(func() {
		_IpRange = &IpRange{}
	})
	return _IpRange
}

func power(x int, n int) uint {
	if n == 0 {
		return 1
	} else {
		return uint(x) * power(x, n-1)
	}
}

// 获取网段的IP地址列表
// 返回IP列表+错误信息
func (p *IpRange) IpRangeToIpList(Ipaddr string) ([]string, error) {
	ipRangeList := strings.Split(Ipaddr, "/")
	if len(ipRangeList) != 2 {
		return nil, errors.New("IP地址格式错误！")
	}
	ip := ipRangeList[0]
	mask, err := strconv.Atoi(ipRangeList[1])
	if err != nil {
		return nil, errors.New("子网掩码转整型错误！")
	}
	var result []string
	if mask > 32 || mask < 0 {
		return nil, errors.New("子网掩码超出范围！")
	}

	/*
		0000 0000 0000 0000 0000 0000 0000 0000
		1111 1111 1111 1111 1111 1111 1111 1111
		192.168.188.1/24  <=> 3232283649
		1100 0000 1010 1000 1011 1100 0000 0001
	*/
	var maskMax uint = 0
	var maskMin uint = 0
	for i := 0; i < 32; i++ {
		if i < 32-mask {
			maskMin += 1 * power(2, i)
		} else {
			maskMax += 1 * power(2, i)
		}
	}

	ipInt := p.IpStringToInt(ip)
	ipIntStart := uint(ipInt) & maskMax
	ipIntEnd := uint(ipInt) | maskMin

	for i := ipIntStart; i <= ipIntEnd; i++ {
		result = append(result, p.IpIntToString(int(i)))
	}

	return result, nil
}

// 将IP字符串转成数值类型
// 返回数值类型IP
func (p *IpRange) IpStringToInt(ipString string) int {
	ipSegments := strings.Split(ipString, ".")
	var ipInt = 0
	var pos uint = 24
	for _, ipSegment := range ipSegments {
		tempInt, _ := strconv.Atoi(ipSegment)
		tempInt = tempInt << pos
		ipInt = ipInt | tempInt
		pos -= 8
	}
	return ipInt
}

// 将IP数值转成字符串类型
// 返回字符类型IP
func (p *IpRange) IpIntToString(ipInt int) string {
	ipSegments := make([]string, 4)
	var length = len(ipSegments)
	buffer := bytes.NewBufferString("")
	for i := 0; i < length; i++ {
		tempInt := ipInt & 0xFF
		ipSegments[length-i-1] = strconv.Itoa(tempInt)
		ipInt = ipInt >> 8
	}
	for i := 0; i < length; i++ {
		buffer.WriteString(ipSegments[i])
		if i < length-1 {
			buffer.WriteString(".")
		}
	}
	return buffer.String()
}

func CheckIp(ip string) (bool, string) {
	ip = strings.ReplaceAll(ip, " ", "")
	check := false
	if strings.Index(ip, "-") > 0 {
		status, Scope := LastCheckIp(ip)
		if status {
			check = true
			return check, Scope
		}
	}
	if strings.Index(ip, "/") > 0 {
		status, Scope := PrefixIp(ip)
		if status {
			check = true
			return check, Scope
		}
	}
	status, Scope := CheckIpStr(ip)
	if status == true {
		check = true
		return check, Scope
	}
	return check, ""
}

func CheckPort(port string) bool {
	if strings.Index(port, "-") > 0 {
		portList := strings.Split(port, "-")
		if portInt, err := strconv.Atoi(portList[0]); err != nil || portInt < 0 || portInt > 65535 {
			return false
		}
		if portInt, err := strconv.Atoi(portList[1]); err != nil || portInt < 0 || portInt > 65535 {
			return false
		}
	} else {
		if portInt, err := strconv.Atoi(port); err != nil || portInt < 0 || portInt > 65535 {
			return false
		}

	}
	return true
}

func CheckIpStr(ip string) (bool, string) {
	MaxIp := ""
	MinIp := ""
	address := net.ParseIP(ip)
	if address != nil {
		MaxIp += ip
		MinIp += ip
		return true, MaxIp + "-" + MinIp
	} else {
		return false, ""
	}

}

// last格式，比如：192.168.1.0-192.168.1.255
func LastCheckIp(ip string) (bool, string) {
	ipList := strings.Split(ip, "-")
	if status, _ := CheckIpStr(ipList[0]); status == false {
		return false, ""
	}
	if strings.Index(ipList[1], ".") > 0 {
		status, _ := CheckIpStr(ipList[0])
		if status == false {
			return false, ""
		}
		return status, ip
	} else {
		ipInt, err := strconv.Atoi(ipList[1])
		if err != nil {
			return false, ""
		}
		if ipInt >= 0 && ipInt <= 255 {
			ScopeIpList := strings.Split(ipList[0], ".")
			Scope := ipList[0] + "-" + ScopeIpList[0] + "." + ScopeIpList[1] + "." + ScopeIpList[2] + "." + strconv.Itoa(ipInt)

			return true, Scope
		} else {
			return false, ""
		}

	}
}

// prefix格式，比如：192.168.1.0/24、192.168.1.0/255.255.255.0
func PrefixIp(ip string) (bool, string) {
	ipList := strings.Split(ip, "/")
	if status, _ := CheckIpStr(ipList[0]); status == false {
		return false, ""
	}
	if strings.Index(ipList[1], ".") > 0 {
		return CheckIpStr(ipList[1])
	} else {
		if ipList[1] == "8" || ipList[1] == "16" || ipList[1] == "24" {
			ScopeIpList := strings.Split(ipList[0], ".")
			Scope := ipList[0] + "-"
			switch ipList[1] {
			case "8":
				Scope += ScopeIpList[0] + ".255.255.255"
			case "16":
				Scope += ScopeIpList[0] + "." + ScopeIpList[1] + ".255.255"
			case "":
				Scope += ScopeIpList[0] + "." + ScopeIpList[1] + "." + ScopeIpList[2] + ".255"
			}
			return true, Scope
		} else {
			return false, ""
		}

	}
}
