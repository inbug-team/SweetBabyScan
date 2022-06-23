package task_scan_port_domain

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/config"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_port"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

type taskScanPortDomain struct {
	scan   plugin_scan_port.ScanPort
	config plugin_scan_port.Config
	params models.Params
}

var urls []string
var vulData []models.WaitScanVul
var weakData []models.WaitScanWeak
var index = 2
var savePorts = map[string]interface{}{}
var savePortTxt = []string{"*****************<Domain Port Info>*****************\r\n"}
var aliveDomains = map[string]string{}
var serviceConfig string

// 1.迭代方法
func (t *taskScanPortDomain) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	_domains, _ports, _protocols := data[0], data[1], data[2]
	for _, ip := range _domains.([]string) {
		for _, port := range _ports.([]uint) {
			for _, protocol := range _protocols.([]string) {
				wg.Add(1)
				worker <- true
				go task(wg, worker, result, ip, port, protocol)
			}
		}
	}
}

// 2.任务方法
func (t *taskScanPortDomain) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	domain, port, protocol := data[0], data[1], data[2]

	target := plugin_scan_port.Target{
		Host:     domain.(string),
		Port:     port.(uint),
		Protocol: protocol.(string),
	}
	res, err, status := t.scan.Explore(target, &t.config)
	if err == nil && status {
		result <- utils.CountResult{
			Count:  1,
			Result: res,
		}
	} else {
		result <- utils.CountResult{
			Count:  1,
			Result: nil,
		}
	}

	<-worker
}

// 3.保存结果
func (t *taskScanPortDomain) doDone(item interface{}) error {
	result := item.(plugin_scan_port.Result)

	service := "其他"

	if strings.HasPrefix(result.Service.Banner, "HTTP") {
		service = "HTTP"
		urls = append(urls, fmt.Sprintf("http://%s:%d", result.Host, result.Port))
		urls = append(urls, fmt.Sprintf("https://%s:%d", result.Host, result.Port))
	} else if result.Service.Name == "redis" || result.ProbeName == "redis-server" {
		service = "redis"
	} else if result.Service.Name == "ssh" {
		service = "ssh"
	} else if result.Service.Name == "mongodb" || result.ProbeName == "mongodb" {
		service = "mongodb"
	} else if result.Service.Name == "mysql" {
		service = "mysql"
	} else if result.ProbeName == "ms-sql-s" {
		service = "sqlserver"
	} else if result.Service.Name == "ftp" {
		service = "ftp"
	} else if result.Service.Name == "postgresql" {
		service = "postgres"
	} else if result.Service.Name == "oracle" {
		service = "oracle"
	} else if result.Service.Name == "clickhouse" {
		service = "clickhouse"
	} else if result.Service.Name == "elasticsearch" {
		service = "elasticsearch"
	} else if result.Service.Name == "snmp" || result.ProbeName == "SNMPv1public" || result.ProbeName == "SNMPv3GetRequest" {
		service = "snmp"
	} else if result.ProbeName == "SMBProgNeg" {
		service = "smb"
	} else if result.Port == 3389 {
		service = "rdp"
	} else if result.ProbeName == "Memcache" || result.Service.Name == "memcached" || result.ProbeName == "memcached" {
		service = "memcached"
	}

	data := models.ScanPort{
		Domain:          result.Target.Host,
		Port:            fmt.Sprintf(`%d`, result.Target.Port),
		Protocol:        result.Target.Protocol,
		Service:         result.Service.Name,
		ServiceCategory: service,
		Product:         result.Service.Extras.VendorProduct,
		Version:         result.Service.Extras.Version,
		Banner:          result.Service.Banner,
		Cpe:             result.Service.Extras.CPE,
		Type:            result.Service.Extras.DeviceType,
		Os:              result.Service.Extras.OperatingSystem,
		Name:            result.Service.Extras.Hostname,
		Other:           result.Service.Extras.Info,
		Probe:           result.ProbeName,
	}

	savePorts[fmt.Sprintf("A%d", index)] = data.Domain
	savePorts[fmt.Sprintf("B%d", index)], _ = strconv.Atoi(data.Port)
	savePorts[fmt.Sprintf("C%d", index)] = data.Service
	savePorts[fmt.Sprintf("D%d", index)] = data.Probe

	savePortTxt = append(savePortTxt, fmt.Sprintf(
		`%s:%d [%s] [%s] [%s]`,
		result.Target.Host,
		result.Target.Port,
		result.Target.Protocol,
		result.Service.Name,
		result.ProbeName,
	)+"\r\n")
	index++

	if t.params.NoScanHost {
		aliveDomains[data.Domain] = "1"
	}

	if data.Port == "135" || data.Port == "139" || data.Port == "445" {
		vulData = append(vulData, models.WaitScanVul{
			Host: data.Domain,
			Port: result.Target.Port,
			Item: data,
		})
	}

	if utils.Contains(strings.Split(serviceConfig, ","), service) >= 0 {
		weakData = append(weakData, models.WaitScanWeak{
			Host:     data.Domain,
			Port:     data.Port,
			Service:  service,
			Probe:    data.Probe,
			Protocol: data.Protocol,
		})
	}

	if t.params.IsLog {
		fmt.Println(fmt.Sprintf(
			`[+]发现域名端口服务 %s:%d [%s] [%s] [%s]`,
			result.Target.Host,
			result.Target.Port,
			result.Target.Protocol,
			result.Service.Name,
			result.ProbeName,
		))
	}

	return nil
}

// 4.记录数量
func (t *taskScanPortDomain) doAfter(data uint) {

}

// 执行并发扫描
func DoTaskScanPortDomain(req models.Params, _index int) ([]string, []models.WaitScanVul, []models.WaitScanWeak) {
	index = _index
	domains := req.Domains
	ports := req.Ports
	protocols := req.Protocols
	totalTask := len(domains) * len(ports) * len(protocols)

	serviceConfig = req.ServiceScanWeak
	if serviceConfig == "" {
		serviceConfig = config.Service
	}
	var s plugin_scan_port.ScanPort
	s.InitContent(req.RuleProbe)

	task := taskScanPortDomain{
		scan:   s,
		params: req,
		config: plugin_scan_port.Config{
			Rarity:         req.Rarity,
			TimeoutConnect: time.Duration(req.TimeOutScanPortConnect) * time.Second,
			TimeoutSend:    time.Duration(req.TimeOutScanPortSend) * time.Second,
			TimeoutRead:    time.Duration(req.TimeOutScanPortRead) * time.Second,
			NULLProbeOnly:  req.IsNULLProbeOnly,
			UseAllProbes:   req.IsUseAllProbes,
		},
	}

	_totalTask := uint(totalTask)
	totalTime := uint(math.Ceil(float64(_totalTask)/float64(req.WorkerScanPort)) * float64(req.TimeOutScanPortConnect+req.TimeOutScanPortRead+req.TimeOutScanPortSend))

	utils.MultiTask(
		_totalTask,
		uint(req.WorkerScanPort),
		totalTime,
		task.doIter,
		task.doTask,
		task.doDone,
		task.doAfter,
		fmt.Sprintf(
			"开始域名端口服务扫描\r\n\r\n> 扫描并发：%d\r\n> 连接超时：%d\r\n> 发包超时：%d\r\n> 读包超时：%d\r\n> 扫描端口：%s\r\n> 扫描协议：%s\n",
			req.WorkerScanPort,
			req.TimeOutScanPortConnect,
			req.TimeOutScanPortSend,
			req.TimeOutScanPortRead,
			req.Port,
			req.Protocol,
		),
		"完成域名端口服务扫描",
		func() {
			// 保存数据-端口信息
			savePortTxt = append(savePortTxt, "*****************<Domain Port Info>*****************\r\n\r\n")
			utils.SaveData(req.OutputExcel, "端口信息", savePorts)
			utils.SaveText(req.OutputTxt, savePortTxt)

			if req.NoScanHost {
				// 保存数据-存活域名
				saveDomains := map[string]interface{}{}
				saveDomainTxt := []string{"*****************<Domain>*****************\r\n"}
				indexDomains := 2
				for v := range aliveDomains {
					saveDomains[fmt.Sprintf("A%d", indexDomains)] = v
					saveDomainTxt = append(saveDomainTxt, fmt.Sprintf("%s\r\n", v))
					indexDomains++
				}
				saveDomainTxt = append(saveDomainTxt, "*****************<Domain>*****************\r\n\r\n")
				utils.SaveData(req.OutputExcel, "存活主机", saveDomains)
				utils.SaveText(req.OutputTxt, saveDomainTxt)
			}

		},
		domains,
		ports,
		protocols,
	)

	return urls, vulData, weakData
}
