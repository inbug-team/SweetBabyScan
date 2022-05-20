package plugin_scan_port

import (
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 获取探针数据包指令
func (p *Probe) getDirectiveSyntax(data string) (directive Directive) {
	directive = Directive{}
	if strings.Count(data, " ") <= 0 {
		panic("错误的指令格式")
	}
	blankIndex := strings.Index(data, " ")
	directiveName := data[:blankIndex]
	Flag := data[blankIndex+1 : blankIndex+2]
	delimiter := data[blankIndex+2 : blankIndex+3]
	directiveStr := data[blankIndex+3:]

	directive.DirectiveName = directiveName
	directive.Flag = Flag
	directive.Delimiter = delimiter
	directive.DirectiveStr = directiveStr

	return directive
}

// 解析探针协议、服务、指令
func (p *Probe) parseProbeInfo(probeStr string) {
	proto := probeStr[:3]
	other := probeStr[4:]

	if !(proto == "TCP" || proto == "UDP") {
		panic("探针的协议必须是TCP或UDP其中一中")
	}
	if len(other) == 0 {
		panic("没有探针指令")
	}

	directive := p.getDirectiveSyntax(other)

	p.Name = directive.DirectiveName
	p.Data = strings.Split(directive.DirectiveStr, directive.Delimiter)[0]
	p.Protocol = strings.ToLower(strings.TrimSpace(proto))
}

// 获取正则
func (p *Probe) getMatch(data string) (match Match, err error) {
	match = Match{}
	matchText := data[len("match")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplit := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplit[0], strings.Join(textSplit[1:], "")

	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return match, ok
	}
	match.Service = directive.DirectiveName
	match.Pattern = pattern
	match.PatternCompiled = patternCompiled
	match.VersionInfo = versionInfo
	return match, nil
}

// 获取软件正则
func (p *Probe) getSoftMatch(data string) (softMatch Match, err error) {
	softMatch = Match{IsSoft: true}

	matchText := data[len("softmatch")+1:]
	directive := p.getDirectiveSyntax(matchText)

	textSplit := strings.Split(directive.DirectiveStr, directive.Delimiter)

	pattern, versionInfo := textSplit[0], strings.Join(textSplit[1:], "")
	patternUnescaped, _ := DecodePattern(pattern)
	patternUnescapedStr := string([]rune(string(patternUnescaped)))
	patternCompiled, ok := regexp.Compile(patternUnescapedStr)
	if ok != nil {
		return softMatch, ok
	}

	softMatch.Service = directive.DirectiveName
	softMatch.Pattern = pattern
	softMatch.PatternCompiled = patternCompiled
	softMatch.VersionInfo = versionInfo

	return softMatch, nil
}

// 解析端口
func (p *Probe) parsePorts(data string) {
	p.Ports = data[len("ports")+1:]
}

// 解析ssl端口
func (p *Probe) parseSSLPorts(data string) {
	p.SSLPorts = data[len("sslports")+1:]
}

// 解析总等待时间
func (p *Probe) parseTotalWaitMS(data string) {
	p.TotalWaitMS, _ = strconv.Atoi(data[len("totalwaitms")+1:])
}

// 解析tcp封包的时间
func (p *Probe) parseTCPWrappedMS(data string) {
	p.TCPWrappedMS, _ = strconv.Atoi(data[len("tcpwrappedms")+1:])
}

// 解析rarity
func (p *Probe) parseRarity(data string) {
	p.Rarity, _ = strconv.Atoi(data[len("rarity")+1:])
}

// 解析fallback
func (p *Probe) parseFallback(data string) {
	p.Fallback = data[len("fallback")+1:]
}

// 解析探针字符串
func (p *Probe) parseFromString(data string) {
	data = strings.TrimSpace(data)
	lines := strings.Split(data, "\n")
	probeStr := lines[0]
	p.parseProbeInfo(probeStr)

	var matches []Match
	for _, line := range lines {
		if strings.HasPrefix(line, "match ") {
			match, err := p.getMatch(line)
			if err != nil {
				continue
			}
			matches = append(matches, match)
		} else if strings.HasPrefix(line, "softmatch ") {
			softMatch, err := p.getSoftMatch(line)
			if err != nil {
				continue
			}
			matches = append(matches, softMatch)
		} else if strings.HasPrefix(line, "ports ") {
			p.parsePorts(line)
		} else if strings.HasPrefix(line, "sslports ") {
			p.parseSSLPorts(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "totalwaitms ") {
			p.parseTotalWaitMS(line)
		} else if strings.HasPrefix(line, "tcpwrappedms ") {
			p.parseTCPWrappedMS(line)
		} else if strings.HasPrefix(line, "rarity ") {
			p.parseRarity(line)
		} else if strings.HasPrefix(line, "fallback ") {
			p.parseFallback(line)
		}
	}
	p.Matches = &matches

}

// 获取长度
func (ps ProbesRarity) Len() int {
	return len(ps)
}

// 交换位置
func (ps ProbesRarity) Swap(i, j int) {
	ps[i], ps[j] = ps[j], ps[i]
}

// 判断大小
func (ps ProbesRarity) Less(i, j int) bool {
	return ps[i].Rarity < ps[j].Rarity
}

// 对探测结果排序
func sortProbesByRarity(probes []Probe) (probesSorted []Probe) {
	probesToSort := ProbesRarity(probes)
	sort.Stable(probesToSort)
	// 稳定排序 ， 探针发送顺序不同，最后会导致探测服务出现问题
	probesSorted = probesToSort
	return probesSorted
}
