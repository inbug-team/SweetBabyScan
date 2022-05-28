package structs

import (
	"net/http"
	"strings"
	"time"
)

var (
	CeYeApi                  string
	CeYeDomain               string
	ReversePlatformType      ReverseType
	DnsLogCNGetDomainRequest *http.Request
	DnsLogCNGetRecordRequest *http.Request
)

func InitReversePlatform(api, domain string, timeout time.Duration) {
	if api != "" && domain != "" && strings.HasSuffix(domain, ".ceye.io") {
		CeYeApi = api
		CeYeDomain = domain
		ReversePlatformType = ReverseTypeCeYe
	} else {
		ReversePlatformType = ReverseTypeDnsLogCN

		// 设置请求相关参数
		DnsLogCNGetDomainRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getdomain.php", nil)
		DnsLogCNGetRecordRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getrecords.php", nil)

	}
}
