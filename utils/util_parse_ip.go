package utils

import (
	"errors"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var ParseIPErr = errors.New("主机解析错误，格式：\n" +
	"format: \n" +
	"192.168.1.1\n" +
	"192.168.1.1/8\n" +
	"192.168.1.1/16\n" +
	"192.168.1.1/24\n" +
	"192.168.1.1/25\n" +
	"192.168.1.1/32\n" +
	"192.168.1.1,192.168.1.2\n" +
	"192.168.1.1-192.168.255.255\n" +
	"192.168.1.1-255")

// 获取IP列表
func GetIps(ipStr, ipStrBlack string) (ips []int) {
	whiteList, err := ParseIP(ipStr)
	if err != nil {
		return ips
	}

	blackList, err := ParseIP(ipStrBlack)
	if err != nil {
		return ips
	}

	ips = Difference(whiteList, blackList)
	Shuffle(ips)

	return ips
}

// 解析IP字符串
func ParseIP(ip string) (hosts []int, err error) {

	if ip != "" {
		hosts, err = ParseIPs(ip)
	}

	hosts = RemoveDuplicate(hosts)
	return hosts, err
}

// 解析多个IP
func ParseIPs(ip string) (hosts []int, err error) {
	ip = strings.ReplaceAll(ip, "，", ",")
	ip = strings.ReplaceAll(ip, ";", ",")
	ip = strings.ReplaceAll(ip, "；", ",")
	ip = strings.ReplaceAll(ip, "、", ",")
	if strings.Contains(ip, ",") {
		return IPSplit(ip, ",")
	} else if strings.Contains(ip, "\n") {
		return IPSplit(ip, "\n")
	} else {
		hosts, err = ParseIPone(ip)
		return hosts, err
	}
}

// IP分隔
func IPSplit(ip, sep string) (hosts []int, err error) {
	IPList := strings.Split(ip, sep)
	var ips []int
	for _, ip := range IPList {
		ips, err = ParseIPone(ip)
		if err != nil {
			return hosts, err
		}
		hosts = append(hosts, ips...)
	}
	return hosts, err
}

// 解析单个IP
func ParseIPone(ip string) ([]int, error) {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Contains(ip, "/"):
		ipRange := NewIpRangeLib()
		ips, err := ipRange.IpRangeToIpList(ip)
		return ips, err
	case strings.Count(ip, "-") == 1:
		return ParseIPC(ip)
	case reg.MatchString(ip):
		_, err := net.LookupHost(ip)
		if err != nil {
			return nil, err
		}
		return []int{IpStringToInt(ip)}, nil
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil, ParseIPErr
		}
		return []int{IpStringToInt(ip)}, nil
	}
}

//解析IP段，例如：192.168.111.1-255,192.168.111.1-192.168.112.255
func ParseIPC(ip string) ([]int, error) {
	IPRange := strings.Split(ip, "-")
	testIP := net.ParseIP(IPRange[0])
	var AllIP []int
	if len(IPRange[1]) < 4 {
		Range, err := strconv.Atoi(IPRange[1])
		if testIP == nil || Range > 255 || err != nil {
			return nil, ParseIPErr
		}
		SplitIP := strings.Split(IPRange[0], ".")
		ip1, err1 := strconv.Atoi(SplitIP[3])
		ip2, err2 := strconv.Atoi(IPRange[1])
		PrefixIP := strings.Join(SplitIP[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return nil, ParseIPErr
		}
		for i := ip1; i <= ip2; i++ {
			AllIP = append(AllIP, IpStringToInt(PrefixIP+"."+strconv.Itoa(i)))
		}
	} else {
		SplitIP1 := strings.Split(IPRange[0], ".")
		SplitIP2 := strings.Split(IPRange[1], ".")
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil, ParseIPErr
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return nil, ParseIPErr
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			AllIP = append(AllIP, IpStringToInt(ip))
		}
	}

	return AllIP, nil

}

// 去重
func RemoveDuplicate(old []int) []int {
	result := make([]int, 0, len(old))
	temp := map[int]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// IP转数字
func InetAtoN(ip string) int64 {
	ret := big.NewInt(0)
	ret.SetBytes(net.ParseIP(ip).To4())
	return ret.Int64()
}
