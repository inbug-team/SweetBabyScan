package task_scan_host_ip

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_host"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"github.com/jedib0t/go-pretty/v6/table"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

type taskScanHostIP struct {
	params models.Params
}

var ip []int

var (
	ipRange = map[string]int{}
)

var indexIps = 2

// 1.迭代方法
func (t *taskScanHostIP) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	items := data[0]
	for _, item := range items.([]int) {
		wg.Add(1)
		worker <- true
		go task(wg, worker, result, item)
	}
}

// 2.任务方法
func (t *taskScanHostIP) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	item := data[0].(int)
	status := false
	methodAlive := t.params.MethodScanHost
	mac := ""
	_ip := utils.IpIntToString(item)
	if methodAlive == "ICMP" {
		status = plugin_scan_host.ScanHostByICMP(_ip, time.Duration(t.params.TimeOutScanHost)*time.Second)
	} else if methodAlive == "PING" {
		status = plugin_scan_host.ScanHostByPing(_ip)
	}
	if status {
		result <- utils.CountResult{
			Count: 1,
			Result: models.ScanHost{
				Ip:      _ip,
				IpNum:   item,
				IpRange: strings.Join(strings.Split(_ip, ".")[0:3], ".") + ".1/24",
				Mac:     mac,
			},
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
func (t *taskScanHostIP) doDone(item interface{}) error {
	result := item.(models.ScanHost)
	if _, ok := ipRange[result.IpRange]; ok {
		ipRange[result.IpRange] += 1
	} else {
		ipRange[result.IpRange] = 1
	}
	ip = append(ip, result.IpNum)

	if t.params.IsLog {
		fmt.Println(fmt.Sprintf("[+]发现存活主机 %s", result.Ip))
	}

	return nil
}

// 4.记录数量
func (t *taskScanHostIP) doAfter(data uint) {

}

// 执行并发存活检测
func DoTaskScanHostIP(req models.Params) ([]int, int) {
	task := taskScanHostIP{params: req}

	totalTask := uint(len(req.IPs))
	totalTime := uint(math.Ceil(float64(totalTask)/float64(req.WorkerScanHost)) * float64(req.TimeOutScanHost))

	utils.MultiTask(
		totalTask,
		uint(req.WorkerScanHost),
		totalTime,
		task.doIter,
		task.doTask,
		task.doDone,
		task.doAfter,
		fmt.Sprintf(
			"开始IP主机存活检测\r\n\r\n> 存活并发：%d\r\n> 存活超时：%d\r\n> 检测方式：%s\r\n> 检测网段：%s\r\n> 排除网段：%s\r\n",
			req.WorkerScanHost,
			req.TimeOutScanHost,
			req.MethodScanHost,
			req.Host,
			req.HostBlack,
		),
		"完成IP主机存活检测",
		func() {
			var listIpRange []models.IpRangeStruct
			total := 0
			for k, v := range ipRange {
				listIpRange = append(listIpRange, models.IpRangeStruct{Key: k, Value: v})
				total += v
			}
			sort.Slice(listIpRange, func(i, j int) bool {
				return listIpRange[i].Value > listIpRange[j].Value
			})

			var segments []table.Row
			id := 1
			for _, v := range listIpRange {
				segments = append(segments, table.Row{id, v.Key, v.Value})
				id++
			}
			utils.ShowTable(
				fmt.Sprintf("共发现：%d个网段，%d个IP", len(listIpRange), total),
				table.Row{"#", "IP SEGMENT", "TOTAL"},
				segments,
			)

			// 保存数据-存活IP
			saveIps := map[string]interface{}{}
			saveIpTxt := []string{"*****************<IP>*****************\r\n"}
			for _, v := range ip {
				_v := utils.IpIntToString(v)
				saveIps[fmt.Sprintf("A%d", indexIps)] = _v
				saveIpTxt = append(saveIpTxt, fmt.Sprintf("%s\r\n", _v))
				indexIps++
			}
			saveIpTxt = append(saveIpTxt, "*****************<IP>*****************\r\n\n")

			utils.SaveData(req.OutputExcel, "存活主机", saveIps)
			utils.SaveText(req.OutputTxt, saveIpTxt)

			// 保存数据-IP段
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
		},
		req.IPs,
	)
	return ip, indexIps
}
