package plugin_scan_poc_nuclei

import (
	"fmt"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"go.uber.org/ratelimit"
)

var (
	ExecOptions protocols.ExecuterOptions
)

type VulResult struct {
	Status   bool
	Response string
	Request  string
}

type Poc struct {
	Template    *templates.Template
	PocProtocol string
	VulLevel    string
}

// 初始化nuclei选项
func InitPocNucleiExecOpts(rate int, timeout int) {
	fakeWriter := &FakeWrite{}
	progress := &FakeProgress{}
	o := types.Options{
		RateLimit:               rate,
		BulkSize:                25,
		TemplateThreads:         25,
		HeadlessBulkSize:        10,
		HeadlessTemplateThreads: 10,
		Timeout:                 timeout,
		Retries:                 1,
		MaxHostError:            30,
	}
	err := protocolinit.Init(&o)
	if err != nil {
		fmt.Println("protocol init error !")
		return
	}

	catalog2 := catalog.New("")
	ExecOptions = protocols.ExecuterOptions{
		Output:      fakeWriter,
		Options:     &o,
		Progress:    progress,
		Catalog:     catalog2,
		RateLimiter: ratelimit.New(rate),
	}
}

// 加载POC
func ParsePocNucleiFile(filePath string) (tpl *templates.Template, err error) {
	tpl, err = templates.Parse(filePath, nil, ExecOptions)
	return
}

// 执行单元
func ExecutePocNuclei(url string, poc *templates.Template) (VulResult, error) {
	ret := VulResult{}
	e := poc.Executer
	err := e.ExecuteWithResults(url, func(result *output.InternalWrappedEvent) {
		if result != nil {
			for _, r := range result.Results {
				if r != nil {
					if r.MatcherStatus {
						ret.Status = r.MatcherStatus
						ret.Request = r.Request
						ret.Response = r.Response
						return
					}
				}
			}
		}
	})
	return ret, err
}

// 扫描nuclei
func ScanPocNuclei(url string, p *Poc) (success bool, packetSend string, packetRecv string, err error) {
	if p != nil && p.Template != nil {
		res, err := ExecutePocNuclei(url, p.Template)
		if err != nil {
			return
		}
		success = res.Status
		packetSend = res.Request
		packetRecv = res.Response
	}

	return
}
