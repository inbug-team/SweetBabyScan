package plugin_scan_port

import (
	"regexp"
	"strconv"
	"strings"
)

// 对获取到的 Banner 进行正则匹配
func (m *Match) MatchPattern(response []byte) (matched bool) {
	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)
	// 匹配结果大于 0 表示规则与 response 匹配成功
	if len(foundItems) > 0 {
		matched = true
		return
	}
	return false
}

// 解析版本信息
func (m *Match) ParseVersionInfo(response []byte) Extras {
	var extras = Extras{}

	responseStr := string([]rune(string(response)))
	foundItems := m.PatternCompiled.FindStringSubmatch(responseStr)

	versionInfo := m.VersionInfo
	foundItems = foundItems[1:]
	for index, value := range foundItems {
		dollarName := "$" + strconv.Itoa(index+1)
		versionInfo = strings.Replace(versionInfo, dollarName, value, -1)
	}

	v := versionInfo
	if strings.Contains(v, " p/") {
		regex := regexp.MustCompile(`p/([^/]*)/`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " p|") {
		regex := regexp.MustCompile(`p|([^|]*)|`)
		vendorProductName := regex.FindStringSubmatch(v)
		extras.VendorProduct = vendorProductName[1]
	}
	if strings.Contains(v, " v/") {
		regex := regexp.MustCompile(`v/([^/]*)/`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " v|") {
		regex := regexp.MustCompile(`v|([^|]*)|`)
		version := regex.FindStringSubmatch(v)
		extras.Version = version[1]
	}
	if strings.Contains(v, " i/") {
		regex := regexp.MustCompile(`i/([^/]*)/`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " i|") {
		regex := regexp.MustCompile(`i|([^|]*)|`)
		info := regex.FindStringSubmatch(v)
		extras.Info = info[1]
	}
	if strings.Contains(v, " h/") {
		regex := regexp.MustCompile(`h/([^/]*)/`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " h|") {
		regex := regexp.MustCompile(`h|([^|]*)|`)
		hostname := regex.FindStringSubmatch(v)
		extras.Hostname = hostname[1]
	}
	if strings.Contains(v, " o/") {
		regex := regexp.MustCompile(`o/([^/]*)/`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " o|") {
		regex := regexp.MustCompile(`o|([^|]*)|`)
		operatingSystem := regex.FindStringSubmatch(v)
		extras.OperatingSystem = operatingSystem[1]
	}
	if strings.Contains(v, " d/") {
		regex := regexp.MustCompile(`d/([^/]*)/`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " d|") {
		regex := regexp.MustCompile(`d|([^|]*)|`)
		deviceType := regex.FindStringSubmatch(v)
		extras.DeviceType = deviceType[1]
	}
	if strings.Contains(v, " cpe:/") {
		regex := regexp.MustCompile(`cpe:/([^/]*)/`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	if strings.Contains(v, " cpe:|") {
		regex := regexp.MustCompile(`cpe:|([^|]*)|`)
		cpeName := regex.FindStringSubmatch(v)
		if len(cpeName) > 1 {
			extras.CPE = cpeName[1]
		} else {
			extras.CPE = cpeName[0]
		}
	}
	return extras
}
