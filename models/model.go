package models

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

const (
	S = 1
	M = 60
	H = 60 * 60
)

// Poc脚本-Xray
type DataPocXray struct {
	Name   string              `yaml:"name"`
	Set    map[string]string   `yaml:"set"`
	Sets   map[string][]string `yaml:"sets"`
	Rules  []Rules             `yaml:"rules"`
	Groups map[string][]Rules  `yaml:"groups"`
	Detail Detail              `yaml:"detail"`
}

type Rules struct {
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	Search          string            `yaml:"search"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Expression      string            `yaml:"expression"`
}

type Detail struct {
	Author      string   `yaml:"author"`
	Links       []string `yaml:"links"`
	Description string   `yaml:"description"`
	Version     string   `yaml:"version"`
}

// Poc脚本-Nuclei
type DataPocNuclei struct {
	Template    *templates.Template
	PocName     string `json:"poc_name"`     // poc名称
	PocScript   string `json:"poc_script"`   // 脚本详情
	PocCatalog  string `json:"poc_catalog"`  // poc类型
	PocProtocol string `json:"poc_protocol"` // poc协议类型
	VulLevel    string `json:"vul_level"`    // 严重等级
}

// 网站指纹
type Fingerprints struct {
	Apps map[string]Fingerprint `json:"technologies"`
}

type Fingerprint struct {
	CSS     interface{}            `json:"css"`
	Cookies map[string]string      `json:"cookies"`
	JS      map[string]string      `json:"js"`
	Headers map[string]string      `json:"headers"`
	HTML    interface{}            `json:"html"`
	Script  interface{}            `json:"script"`
	Meta    map[string]interface{} `json:"meta"`
	Implies interface{}            `json:"implies"`
	Icon    interface{}            `json:"icon"`
}

// 输出指纹
type OutputFingerprints struct {
	Apps map[string]OutputFingerprint `json:"apps"`
}

type OutputFingerprint struct {
	Cookies map[string]string   `json:"cookies,omitempty"`
	JS      []string            `json:"js,omitempty"`
	Headers map[string]string   `json:"headers,omitempty"`
	HTML    []string            `json:"html,omitempty"`
	Script  []string            `json:"script,omitempty"`
	CSS     []string            `json:"css,omitempty"`
	Meta    map[string][]string `json:"meta,omitempty"`
	Implies []string            `json:"implies,omitempty"`
	Icon    string              `json:"icon"`
}

// IP段统计
type IpRangeStruct struct {
	Key   string
	Value int
}

// 命令行参数
type Params struct {
	FileDate               string                         // 文件日期
	OutputExcel            string                         // 保存文件-excel
	OutputTxt              string                         // 保存文件-txt
	Host                   string                         // 检测网段
	Domain                 string                         // 检测域名
	Url                    string                         // 链接
	Port                   string                         // 端口
	Protocol               string                         // 协议
	HostBlack              string                         // 排除网段
	MethodScanHost         string                         // 验存方式：PING、ICMP
	WorkerScanHost         int                            // 存活并发
	WorkerScanPort         int                            // 扫描并发
	WorkerScanSite         int                            // 爬虫并发
	IPs                    []int                          // IP集合
	Domains                []string                       // 域名集合
	Urls                   []string                       // URL链接
	Ports                  []uint                         // 端口范围
	Protocols              []string                       // 协议范围
	TimeOutScanHost        int                            // 存活超时
	IsLog                  bool                           // 显示日志
	IsScreen               bool                           // 是否截图
	Rarity                 int                            // 优先级
	TimeOutScanPortConnect int                            // 扫描连接超时
	TimeOutScanPortSend    int                            // 扫描发包超时
	TimeOutScanPortRead    int                            // 扫描读取超时
	TimeOutScanSite        int                            // 爬虫超时
	TimeOutScreen          int                            // 截图超时
	IsNULLProbeOnly        bool                           // 仅使用空探针
	IsUseAllProbes         bool                           // 使用全量探针
	RuleProbe              string                         // 指纹规则
	ListPocNuclei          bool                           // 列举PocNuclei
	ListPocXray            bool                           // 列举PocXray
	FilterPocName          string                         // 筛选Poc名称
	FilterVulLevel         string                         // 筛选漏洞等级
	Sites                  []ScanSite                     // 网站列表
	PocNuclei              []DataPocNuclei                // Poc列表
	PocXray                []DataPocXray                  // Poc列表
	WaitVul                []WaitScanVul                  // 待爬漏洞列表
	TimeOutScanPocNuclei   int                            // PocNuclei扫描超时
	WorkerScanPoc          int                            // Poc并发
	WaitWeak               []WaitScanWeak                 // 待爬漏洞列表
	UserPass               map[string]map[string][]string // 弱口令字典
	GroupScanWeak          int                            // 爆破分组
	TimeOutScanWeak        int                            // 爆破超时
	WorkerScanWeak         string                         // 爆破并发
	WorkerScanWeakMap      map[string]int                 // 爆破并发字典
	NoScanHost             bool                           // 跳过主机存活检测
	NoScanWeak             bool                           // 跳过弱口令爆破
	NoScanVul              bool                           // 跳过高危漏洞探测
	NoScanPoc              bool                           // 跳过POC漏洞探测
	ServiceScanWeak        string                         // 指定爆破协议
	AUser                  string                         // 追加账号字典
	APass                  string                         // 追加密码字典
	WUser                  string                         // 覆盖账号字典
	WPass                  string                         // 覆盖密码字典
	IsAPass                bool                           // 是否追加弱口令生成器
	IsWPass                bool                           // 是否覆盖弱口令生成器
	PasswordPrefix         string                         // 密码前缀
	PasswordCenter         string                         // 密码中位
	PasswordSuffix         string                         // 密码后缀
	PortForward            bool                           // 是否开启端口转发
	SourceHost             string                         // 目标转发主机
	LocalPort              int                            // 本机代理端口
	PortMap                bool                           // 是否开启内网穿透
	PortMapServer          bool                           // 是否开启内网穿透-服务端
	PortMapClient          bool                           // 是否开启内网穿透-客户端
	PortMapClientSock5     bool                           // 是否开启内网穿透-客户端sock5转发
	Secret                 string                         // 密钥
	PortServerListen       int                            // 穿透服务端监听端口
	ServerURI              string                         // 穿透服务端地址
	PortClientMap          string                         // 穿透客户端映射字典，格式：8080-127.0.0.1:8080,9000-192.168.188.1:9000
	Sock5Port              int                            // sock5监听端口
	Sock5AuthUsername      string                         // sock5鉴权账号
	Sock5AuthPassword      string                         // sock5鉴权密码
}

// 主机存活结构
type ScanHost struct {
	Ip      string `json:"ip"`       // ip
	IpNum   int    `json:"ip_num"`   // ip数值
	IpRange string `json:"ip_range"` // ip网段
	Mac     string `json:"mac"`      // mac地址
}

// 端口服务结构
type ScanPort struct {
	Ip              string `json:"ip"`               // ip
	IpNum           int    `json:"ip_num"`           // ip数值
	IpRange         string `json:"ip_range"`         // ip网段
	Domain          string `json:"domain"`           // 域名
	Port            string `json:"port"`             // 端口
	Protocol        string `json:"protocol"`         // 协议
	Service         string `json:"service"`          // 服务
	ServiceCategory string `json:"service_category"` // 服务分类
	Product         string `json:"product"`          // 产品
	Version         string `json:"version"`          // 版本
	Banner          string `json:"banner"`           // Banner
	Cpe             string `json:"cpe"`              // CPE
	Type            string `json:"type"`             // 设备类型
	Os              string `json:"os"`               // 操作系统
	Name            string `json:"name"`             // 主机名称
	Other           string `json:"other"`            // 其他信息
	Probe           string `json:"probe"`            // 探针
}

// 网站爬虫结构
type ScanSite struct {
	Title        string `json:"title"`         // 网站标题
	Link         string `json:"link"`          // 网站链接
	LinkRedirect string `json:"link_redirect"` // 网站跳转连接
	StatusCode   string `json:"status_code"`   // 状态代码
	Host         string `json:"host"`          // 主机
	Port         string `json:"port"`          // 端口
	Keywords     string `json:"keywords"`      // 关键字
	Description  string `json:"description"`   // 网站描述
	Header       string `json:"header"`        // 头部信息
	Image        string `json:"image"`         // 网站截图（大图）
	Tls          string `json:"tls"`           // tls证书
	CmsName      string `json:"cms_name"`      // CMS系统名称
	CmsType      string `json:"cms_type"`      // CMS匹配类型
	CmsRule      string `json:"cms_rule"`      // CMS匹配规则
	CmsMd5Str    string `json:"cms_md5_str"`   // CMS MD5字符串
	CmsMd5Name   string `json:"cms_md5_name"`  // CMS MD5系统名称
	CmsInfo      string `json:"cms_info"`      // CMS信息
}

// POC结构
type ScanPoc struct {
	Url         string `json:"url"`
	Host        string `json:"host"` // 主机
	Port        string `json:"port"` // 端口
	Title       string `json:"title"`
	Keywords    string `json:"keywords"`
	Description string `json:"description"`
	StatusCode  string `json:"status_code"`
	PacketSend  string `json:"packet_send"`
	PacketRecv  string `json:"packet_recv"`
	PocName     string `json:"poc_name"`
	VulName     string `json:"vul_name"`
	VulDesc     string `json:"vul_desc"`
	VulLevel    string `json:"vul_level"`    // 等级
	PocProtocol string `json:"poc_protocol"` // 协议
	PocCatalog  string `json:"poc_catalog"`  // 协议
	CmsName     string `json:"cms_name"`     // CMS系统名称
}

// 爆破结构
type ScanWeak struct {
	Host     string `json:"host"`     // 主机
	Port     string `json:"port"`     // 端口
	Service  string `json:"service"`  // 服务
	Probe    string `json:"probe"`    // 探针
	Protocol string `json:"protocol"` // 协议
	User     string `json:"user"`     // 账号
	Pass     string `json:"pass"`     // 密码
}

// 等待扫描漏洞
type WaitScanVul struct {
	Host string
	Port uint
	Item ScanPort
}

// 等待爆破服务
type WaitScanWeak struct {
	Host     string `json:"host"`     // 主机
	Port     string `json:"port"`     // 端口
	Service  string `json:"service"`  // 服务
	Probe    string `json:"probe"`    // 探针
	Protocol string `json:"protocol"` // 协议
}
