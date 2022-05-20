package utils

import (
	"strconv"
	"strings"
)

// 解析端口字符串
func ParsePort(ports string) []uint {
	var scanPorts []uint
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}

		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := uint(start); i <= uint(end); i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = removeDuplicate(scanPorts)
	return scanPorts
}

// 去除重复
func removeDuplicate(old []uint) []uint {
	result := make([]uint, 0, len(old))
	temp := map[uint]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}
