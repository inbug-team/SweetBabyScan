package plugin_scan_port

import (
	"SweetBabyScan/utils"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// 收发包
func grabResponse(target Target, data []byte, config *Config) ([]byte, error, bool) {
	var response []byte

	addr := target.GetAddress()
	dialer := net.Dialer{
		Timeout: config.TimeoutConnect,
	}

	proto := target.Protocol
	if !(proto == "tcp" || proto == "udp") {
		log.Fatal("不能发送未知协议的请求", proto)
	}

	conn, errConn := dialer.Dial(proto, addr)
	if errConn != nil {
		return response, errConn, false
	}
	defer func() {
		err := conn.Close()
		utils.PrintErr(err)
	}()

	if len(data) > 0 {
		err := conn.SetWriteDeadline(time.Now().Add(config.TimeoutSend))
		if err != nil {
			return response, err, true
		}
		_, errWrite := conn.Write(data)
		if errWrite != nil {
			return response, errWrite, true
		}
	}

	err := conn.SetReadDeadline(time.Now().Add(config.TimeoutRead))
	if err != nil {
		return response, err, true
	}
	for true {
		buff := make([]byte, 1024)
		n, errRead := conn.Read(buff)
		if errRead != nil {
			if len(response) > 0 {
				break
			} else {
				return response, errRead, true
			}
		}
		if n > 0 {
			response = append(response, buff[:n]...)
		}
	}

	return response, nil, true
}

// 解析探针和指纹库
func (s *ScanPort) parseProbesFromContent(content string) {
	// 1.去除空格和注释
	var lines []string

	linesTemp, err := utils.ReadLines(content)
	if err != nil {
		panic("读取指纹库出错")
	}
	for _, line := range linesTemp {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		panic("指纹库为空")
	}

	// 2.判断指纹库第一行
	firstLine := lines[0]
	if !(strings.HasPrefix(firstLine, "Exclude ") || strings.HasPrefix(firstLine, "Probe ")) {
		panic("指纹库必须以Exclude或Probe开头")
	}

	// 3.判断指纹库是否包含Exclude设置
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Exclude ") {
			count += 1
		}
		if count > 1 {
			panic("指纹库只至多包含一个Exclude设置")
		}
	}

	// 4.提取排除项
	s.Exclude = firstLine[len("Exclude")+1:]

	// 5.拆分探针内容
	newServiceContent := "\n" + strings.Join(lines[1:], "\n")
	probeContent := strings.Split(newServiceContent, "\nProbe")[1:]

	// 6.解析探针内容
	var probes []Probe
	for _, probeItem := range probeContent {
		probe := Probe{}
		probe.parseFromString(probeItem)
		probes = append(probes, probe)
	}

	s.Probes = probes
}

// 解析指纹到字典库
func (s *ScanPort) parseProbesToMapKName() {
	var probesMap = map[string]Probe{}
	for _, probe := range s.Probes {
		probesMap[probe.Name] = probe
	}
	s.ProbesMapKName = probesMap
}

// 判断是否包含端口
func (p *Probe) ContainsPort(testPort uint) bool {
	ports := strings.Split(p.Ports, ",")

	// 常规分割判断，Ports 字符串不含端口范围形式 "[start]-[end]"
	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == uint(cmpPort) {
			return true
		}
	}
	// 范围判断检查，拆分 Ports 中诸如 "[start]-[end]" 类型的端口范围进行比较
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == uint(cmpPort) {
					return true
				}
			}
		}
	}
	return false
}

// 判断是否包含ssl端口
func (p *Probe) ContainsSSLPort(testPort int) bool {
	ports := strings.Split(p.SSLPorts, ",")

	// 常规分割判断，Ports 字符串不含端口范围形式 "[start]-[end]"
	for _, port := range ports {
		cmpPort, _ := strconv.Atoi(port)
		if testPort == cmpPort {
			return true
		}
	}
	// 范围判断检查，拆分 Ports 中诸如 "[start]-[end]" 类型的端口范围进行比较
	for _, port := range ports {
		if strings.Contains(port, "-") {
			portRange := strings.Split(port, "-")
			start, _ := strconv.Atoi(portRange[0])
			end, _ := strconv.Atoi(portRange[1])
			for cmpPort := start; cmpPort <= end; cmpPort++ {
				if testPort == cmpPort {
					return true
				}
			}
		}
	}
	return false
}

// Scan 探测目标端口函数，返回探测结果和错误信息
func (s *ScanPort) Explore(target Target, config *Config) (Result, error, bool) {
	var probesUsed []Probe
	if config.UseAllProbes {
		// 使用所有 Probe 探针进行服务识别尝试，忽略 Probe 的 Ports 端口匹配
		for _, probe := range s.Probes {
			if strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
				probesUsed = append(probesUsed, probe)
			}
		}
	} else if config.NULLProbeOnly {
		// 配置仅使用 NULL Probe 进行探测，及不发送任何 Data，只监听端口返回数据
		probesUsed = append(probesUsed, s.ProbesMapKName["NULL"])
	} else {
		// 未进行特殊配置，默认只使用 NULL Probe 和包含了探测端口的 Probe 探针组
		for _, probe := range s.Probes {
			if probe.ContainsPort(target.Port) && strings.ToLower(probe.Protocol) == strings.ToLower(target.Protocol) {
				probesUsed = append(probesUsed, probe)
			}
		}
		// 将默认 NULL Probe 添加到探针列表
		probesUsed = append(probesUsed, s.ProbesMapKName["NULL"])
	}

	// 按 Probe 的 Rarity 升序排列
	probesUsed = sortProbesByRarity(probesUsed)

	// 根据 Config 配置舍弃 probe.Rarity > config.Rarity 的探针
	var probesUsedFiltered []Probe
	for _, probe := range probesUsed {
		if probe.Rarity > config.Rarity {
			continue
		}
		probesUsedFiltered = append(probesUsedFiltered, probe)
	}
	probesUsed = probesUsedFiltered

	result, err, status := s.scanWithProbes(target, &probesUsed, config)

	return result, err, status
}

// 使用探针扫描
func (s *ScanPort) scanWithProbes(target Target, probes *[]Probe, config *Config) (Result, error, bool) {
	var result = Result{Target: target}

	for _, probe := range *probes {
		var response []byte

		probeData, _ := DecodeData(probe.Data)

		// host := fmt.Sprintf("%s:%d(%s)", target.IP, target.Port, target.Protocol)

		// fmt.Printf("[%s]正在尝试探针[%s]，数据包[%s]\n", host, probe.Name, probe.Data)
		response, err, status := grabResponse(target, probeData, config)
		if !status {
			// fmt.Printf("[%s]收发包连接失败\n", host)
			return result, err, false
		}

		// 成功获取 Banner 即开始匹配规则，无规则匹配则直接返回
		if len(response) > 0 {
			// fmt.Printf("[%s]通过探针[%s]获取响应长度为[%s]的响应\n", host, probe.Name, strconv.Itoa(len(response)))
			found := false

			softFound := false
			var softMatch Match

			for _, match := range *probe.Matches {
				matched := match.MatchPattern(response)
				if matched && !match.IsSoft {
					extras := match.ParseVersionInfo(response)

					result.Service.Target = target

					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data
					result.Service.Details.MatchMatched = match.Pattern

					result.Service.Protocol = strings.ToLower(probe.Protocol)
					result.Service.Name = match.Service

					result.Banner = string(response)
					result.BannerBytes = response
					result.Service.Extras = extras

					result.Timestamp = int32(time.Now().Unix())

					found = true

					return result, nil, true
				} else
				// soft 匹配，记录结果
				if matched && match.IsSoft && !softFound {
					// fmt.Printf("[%s]匹配服务：%s，匹配正则：%s\n", host, match.Service, match.Pattern)
					softFound = true
					softMatch = match
				}
			}

			// 当前 Probe 下的 Matches 未匹配成功，使用 Fallback Probe 中的 Matches 进行尝试
			fallback := probe.Fallback
			if _, ok := s.ProbesMapKName[fallback]; ok {
				fbProbe := s.ProbesMapKName[fallback]
				for _, match := range *fbProbe.Matches {
					matched := match.MatchPattern(response)
					if matched && !match.IsSoft {
						extras := match.ParseVersionInfo(response)

						result.Service.Target = target

						result.Service.Details.ProbeName = probe.Name
						result.Service.Details.ProbeData = probe.Data
						result.Service.Details.MatchMatched = match.Pattern

						result.Service.Protocol = strings.ToLower(probe.Protocol)
						result.Service.Name = match.Service

						result.Banner = string(response)
						result.BannerBytes = response
						result.Service.Extras = extras

						result.Timestamp = int32(time.Now().Unix())

						found = true

						return result, nil, true
					} else if matched && match.IsSoft && !softFound {
						// soft 匹配，记录结果
						// fmt.Printf("[%s]匹配服务：%s，匹配正则：%s\n", host, match.Service, match.Pattern)
						softFound = true
						softMatch = match
					}
				}
			}

			if !found {
				if !softFound {
					result.Service.Target = target
					result.Service.Protocol = strings.ToLower(probe.Protocol)

					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data

					result.Banner = string(response)
					result.BannerBytes = response
					result.Service.Name = "unknown"

					result.Timestamp = int32(time.Now().Unix())

					return result, nil, true
				} else {
					result.Service.Target = target
					result.Service.Protocol = strings.ToLower(probe.Protocol)
					result.Service.Details.ProbeName = probe.Name
					result.Service.Details.ProbeData = probe.Data
					result.Service.Details.MatchMatched = softMatch.Pattern
					result.Service.Details.IsSoftMatched = true

					result.Banner = string(response)
					result.BannerBytes = response

					result.Timestamp = int32(time.Now().Unix())

					extras := softMatch.ParseVersionInfo(response)
					result.Service.Extras = extras
					result.Service.Name = softMatch.Service

					return result, nil, true
				}
			}
		}
	}

	return result, errors.New("没有响应"), false
}

// 初始化文件
func (s *ScanPort) InitFile(path string) {
	// 1.读取指纹库
	serviceByte, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("读取文件出错：%s", err))
	}

	serviceContent := string(serviceByte)
	s.parseProbesFromContent(serviceContent)
	s.parseProbesToMapKName()
}

// 从内容初始化
func (s *ScanPort) InitContent(content string) {
	s.parseProbesFromContent(content)
	s.parseProbesToMapKName()
}
