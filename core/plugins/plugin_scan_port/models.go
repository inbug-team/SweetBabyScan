package plugin_scan_port

import (
	"fmt"
	"regexp"
	"time"
)

// 1.扫描任务
type ScanPort struct {
	Exclude        string
	Probes         []Probe
	ProbesMapKName map[string]Probe
}

// 2.探针指纹内容
type Probe struct {
	Name         string
	Data         string
	Protocol     string
	Ports        string
	SSLPorts     string
	TotalWaitMS  int
	TCPWrappedMS int
	Rarity       int
	Fallback     string
	Matches      *[]Match
}

// 3.探针指纹正则
type Match struct {
	IsSoft          bool
	Service         string
	Pattern         string
	VersionInfo     string
	PatternCompiled *regexp.Regexp
}

// 4.探针数据包指令
type Directive struct {
	DirectiveName string
	Flag          string
	Delimiter     string
	DirectiveStr  string
}

// 5.优先级最高的数据包
type ProbesRarity []Probe

// 6.版本信息
type Extras struct {
	VendorProduct   string `json:"vendor_product,omitempty"`
	Version         string `json:"version,omitempty"`
	Info            string `json:"info,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	DeviceType      string `json:"device_type,omitempty"`
	CPE             string `json:"cpe,omitempty"`
}

// 7.待探测的目标端口
type Target struct {
	IP       string `json:"ip"`
	Port     uint   `json:"port"`
	Protocol string `json:"protocol"`
}

// 8.IP:端口封装
func (t *Target) GetAddress() string {
	return fmt.Sprintf(`%s:%d`, t.IP, t.Port)
}

// 9.探测时的参数配置
type Config struct {
	Rarity         int
	TimeoutConnect time.Duration //链接时间
	TimeoutSend    time.Duration //发包时间
	TimeoutRead    time.Duration //读取时间
	NULLProbeOnly  bool
	UseAllProbes   bool
}

// 10.具体的Probe和匹配规则信息
type Details struct {
	ProbeName     string `json:"probe_name"`
	ProbeData     string `json:"probe_data"`
	MatchMatched  string `json:"match_matched"`
	IsSoftMatched bool   `json:"soft_matched"`
}

// 11.端口服务信息
type Service struct {
	Target
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	Banner      string `json:"banner"`
	BannerBytes []byte `json:"banner_bytes"`
	Extras      `json:"extras"`
	Details     `json:"details"`
}

// 12.输出的结果数据
type Result struct {
	Target
	Service   `json:"service"`
	Timestamp int32  `json:"timestamp"`
	Error     string `json:"error"`
}
