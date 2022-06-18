package task_scan_port

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/config"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_port"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type taskScanPort struct {
	scan   plugin_scan_port.ScanPort
	config plugin_scan_port.Config
	params models.Params
}

var urls []string
var vulData []models.WaitScanVul
var weakData []models.WaitScanWeak
var index = 2
var savePorts = map[string]interface{}{}
var savePortTxt = []string{"*****************<Port Info>*****************\r\n"}
var aliveIps = map[string]string{}
var ipRange = map[string]int{}
var serviceConfig string

// 1.迭代方法
func (t *taskScanPort) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	_ips, _ports, _protocols := data[0], data[1], data[2]
	for _, ip := range _ips.([]int) {
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
func (t *taskScanPort) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	ip, port, protocol := data[0], data[1], data[2]

	target := plugin_scan_port.Target{
		IP:       utils.IpIntToString(ip.(int)),
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
func (t *taskScanPort) doDone(item interface{}) error {
	result := item.(plugin_scan_port.Result)

	service := "其他"

	if strings.HasPrefix(result.Service.Banner, "HTTP") {
		service = "HTTP"
		urls = append(urls, fmt.Sprintf("http://%s:%d", result.IP, result.Port))
		urls = append(urls, fmt.Sprintf("https://%s:%d", result.IP, result.Port))
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
	} else if result.ProbeName == "TerminalServer" || result.ProbeName == "TLSSessionReq" || result.ProbeName == "TerminalServerCookie" {
		service = "rdp"
	} else if result.ProbeName == "Memcache" || result.Service.Name == "memcached" || result.ProbeName == "memcached" {
		service = "memcached"
	}

	data := models.ScanPort{
		Ip:              result.Target.IP,
		IpNum:           utils.IpStringToInt(result.Target.IP),
		IpRange:         strings.Join(strings.Split(result.Target.IP, ".")[0:3], ".") + ".1/24",
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
		StatusPo:        "失败",
		User:            "",
		Pwd:             "",
		Probe:           result.ProbeName,
	}

	savePorts[fmt.Sprintf("A%d", index)] = data.Ip
	savePorts[fmt.Sprintf("B%d", index)], _ = strconv.Atoi(data.Port)
	savePorts[fmt.Sprintf("C%d", index)] = data.Service
	savePorts[fmt.Sprintf("D%d", index)] = data.Probe

	savePortTxt = append(savePortTxt, fmt.Sprintf(
		`%s:%d [%s] [%s] [%s]`,
		result.Target.IP,
		result.Target.Port,
		result.Target.Protocol,
		result.Service.Name,
		result.ProbeName,
	)+"\r\n")
	index++

	if t.params.NoScanHost {
		aliveIps[data.Ip] = "1"

		if _, ok := ipRange[data.Ip]; ok {
			ipRange[data.IpRange] += 1
		} else {
			ipRange[data.IpRange] = 1
		}
	}

	if data.Port == "135" || data.Port == "139" || data.Port == "445" {
		vulData = append(vulData, models.WaitScanVul{
			IP:   data.Ip,
			Port: result.Target.Port,
			Item: data,
		})
	}

	if utils.Contains(strings.Split(serviceConfig, ","), service) >= 0 {
		weakData = append(weakData, models.WaitScanWeak{
			Ip:       data.Ip,
			Port:     data.Port,
			Service:  service,
			Probe:    data.Probe,
			Protocol: data.Protocol,
		})
	}

	if t.params.IsLog {
		fmt.Println(fmt.Sprintf(
			`[+]发现端口服务 %s:%d [%s] [%s] [%s]`,
			result.Target.IP,
			result.Target.Port,
			result.Target.Protocol,
			result.Service.Name,
			result.ProbeName,
		))
	}

	return nil
}

// 4.记录数量
func (t *taskScanPort) doAfter(data uint) {

}

// 执行并发扫描
func DoTaskScanPort(req models.Params) ([]string, []models.WaitScanVul, []models.WaitScanWeak) {
	ips := req.IPs
	ports := req.Ports
	protocols := req.Protocols
	totalTask := len(ips) * len(ports) * len(protocols)
	if totalTask == 0 {
		return []string{}, []models.WaitScanVul{}, []models.WaitScanWeak{}
	}

	serviceConfig = req.ServiceScanWeak
	if serviceConfig == "" {
		serviceConfig = config.Service
	}
	var s plugin_scan_port.ScanPort
	s.InitContent(req.RuleProbe)

	task := taskScanPort{
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
			"开始端口服务扫描\r\n\r\n> 扫描并发：%d\r\n> 连接超时：%d\r\n> 发包超时：%d\r\n> 读包超时：%d\r\n> 扫描端口：%s\r\n> 扫描协议：%s\n",
			req.WorkerScanPort,
			req.TimeOutScanPortConnect,
			req.TimeOutScanPortSend,
			req.TimeOutScanPortRead,
			req.Port,
			req.Protocol,
		),
		"完成端口服务扫描",
		func() {
			// 保存数据-端口信息
			savePortTxt = append(savePortTxt, "*****************<Port Info>*****************\r\n\r\n")
			utils.SaveData(req.OutputExcel, "端口信息", savePorts)
			utils.SaveText(req.OutputTxt, savePortTxt)

			if req.NoScanHost {
				// 保存数据-IP段
				var listIpRange []models.IpRangeStruct
				for k, v := range ipRange {
					listIpRange = append(listIpRange, models.IpRangeStruct{Key: k, Value: v})
				}
				sort.Slice(listIpRange, func(i, j int) bool {
					return listIpRange[i].Value > listIpRange[j].Value
				})
				indexIpSegments := 2
				saveIpSegments := map[string]interface{}{}
				saveIpSegmentTxt := []string{"*****************<IP Segment>*****************\r\n"}
				for _, v := range listIpRange {
					saveIpSegments[fmt.Sprintf("A%d", indexIpSegments)] = v.Key
					saveIpSegments[fmt.Sprintf("B%d", indexIpSegments)] = v.Value
					saveIpSegmentTxt = append(saveIpSegmentTxt, fmt.Sprintf("%s -> %d\r\n", v.Key, v.Value))
					indexIpSegments++
				}
				saveIpSegmentTxt = append(saveIpSegmentTxt, "*****************<IP Segment>*****************\r\n\r\n")
				utils.SaveData(req.OutputExcel, "IP段", saveIpSegments)
				utils.SaveText(req.OutputTxt, saveIpSegmentTxt)

				// 保存数据-存活IP
				saveIps := map[string]interface{}{}
				saveIpTxt := []string{"*****************<IP>*****************\r\n"}
				indexIps := 2
				for v := range aliveIps {
					saveIps[fmt.Sprintf("A%d", indexIps)] = v
					saveIpTxt = append(saveIpTxt, fmt.Sprintf("%s\r\n", v))
					indexIps++
				}
				saveIpTxt = append(saveIpTxt, "*****************<IP>*****************\r\n\r\n")
				utils.SaveData(req.OutputExcel, "存活IP", saveIps)
				utils.SaveText(req.OutputTxt, saveIpTxt)
			}

		},
		ips,
		ports,
		protocols,
	)

	return urls, vulData, weakData
}
