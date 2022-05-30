package plugin_scan_poc_nuclei

import (
	"embed"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"go.uber.org/ratelimit"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
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
func InitPocNucleiExecOpts(timeout int) {
	fakeWriter := &FakeWrite{}
	progress := &FakeProgress{}
	o := types.Options{
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
		RateLimiter: ratelimit.NewUnlimited(),
	}
}

// 解析所有Poc Nuclei文件
func ParsePocNucleiFiles(dirNucleiPoc embed.FS) (items []models.DataPocNuclei) {
	err := fs.WalkDir(dirNucleiPoc, ".", func(path string, info fs.DirEntry, err error) error {
		if filepath.Ext(path) == ".yaml" && !strings.HasSuffix(path, "workflow.yaml") {
			catLog := strings.Split(path, "/")[3]
			content, err := dirNucleiPoc.ReadFile(path)
			if err != nil {
				return nil
			}

			if strings.Contains(string(content), ": helpers/") {
				return nil
			}

			template, err := ParsePocNucleiData(content)
			if err != nil {
				return nil
			}

			tType := template.Type().String()
			if (tType != "http") && (tType != "network") {
				tType = "other"
			}

			item := models.DataPocNuclei{
				Template:    template,
				PocName:     path,
				PocScript:   string(content),
				PocCatalog:  catLog,
				PocProtocol: tType,
			}

			level := template.Info.SeverityHolder.Severity.String()
			if level == "" {
				item.VulLevel = "unknown"
			} else {
				item.VulLevel = level
			}
			items = append(items, item)
		}
		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	return items
}

// 解析Poc Nuclei到表格
func ParsePocNucleiToTable(items []models.DataPocNuclei) (rows []table.Row) {
	ID := 1
	for _, poc := range items {
		pocName := strings.TrimLeft(poc.PocName, "probe/pocs/nuclei/")
		rows = append(rows, table.Row{ID, pocName, poc.PocCatalog, poc.PocProtocol, poc.VulLevel})
		ID++
	}
	return
}

// 过滤 Poc Nuclei [表格形式]
func FilterPocNucleiTable(arr []table.Row, fn func(pocName, vulLevel string, params models.Params) bool, p models.Params) (result []table.Row, total int) {
	for _, item := range arr {
		if fn(item[1].(string), item[4].(string), p) {
			result = append(result, item)
		}
	}
	return result, len(result)
}

// 过滤 Poc Nuclei
func FilterPocNucleiData(arr []models.DataPocNuclei, fn func(pocName, vulLevel string, params models.Params) bool, p models.Params) (result []models.DataPocNuclei, total int) {
	for _, item := range arr {
		if fn(item.PocName, item.VulLevel, p) {
			result = append(result, item)
		}
	}
	return result, len(result)
}

// 加载POC
func ParsePocNucleiData(data []byte) (tpl *templates.Template, err error) {
	rootPath, _ := os.Getwd()
	staticPath := filepath.Join(rootPath, "static")
	file, err := ioutil.TempFile(staticPath, `tmp.*.yaml`)
	if err != nil {
		return
	}
	fmt.Println(file.Name())
	defer os.Remove(file.Name())

	if _, err = file.Write(data); err != nil {
		return
	}

	tpl, err = templates.Parse(file.Name(), nil, ExecOptions)
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
func ScanPocNuclei(url string, p *models.DataPocNuclei) (success bool, packetSend string, packetRecv string, err error) {
	if p != nil && p.Template != nil {
		res, err := ExecutePocNuclei(url, p.Template)
		if err != nil {
			return false, "", "", err
		}
		success = res.Status
		packetSend = res.Request
		packetRecv = res.Response
	}

	return
}
