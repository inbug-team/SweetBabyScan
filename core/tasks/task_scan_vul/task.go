package task_scan_vul

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_ms17010"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_net"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_net_bios"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_smb_ghost"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

type taskScanVul struct {
	params models.Params
}

// 1.迭代方法
func (t *taskScanVul) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	items := data[0]
	for _, item := range items.([]models.WaitScanVul) {
		wg.Add(1)
		worker <- true
		go task(wg, worker, result, item)
	}
}

// 2.任务方法
func (t *taskScanVul) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	item := data[0].(models.WaitScanVul)
	tmpResult := make(chan utils.CountResult, 1)

	go func(_item models.WaitScanVul) {
		status := false
		var res interface{}
		// 获取网卡
		if _item.Port == 135 {
			data, _ := plugin_scan_net.ScanNet(_item.IP, uint(t.params.TimeOutScanPortConnect))
			if len(data) > 0 {
				dataStr, _ := json.Marshal(data)
				status = true
				res = map[string]string{
					"type":     "网卡",
					"ip":       _item.IP,
					"port":     strconv.Itoa(int(_item.Port)),
					"protocol": _item.Item.Protocol,
					"content":  string(dataStr),
				}
			}
		}

		// 获取NetBIOS
		if _item.Port == 139 {
			data, err := plugin_scan_net_bios.ScanNetBIOS(_item.IP, _item.Port, uint(t.params.TimeOutScanPortConnect))
			if err == nil {
				status = true
				res = data
			}
		}

		// 探测漏洞
		if _item.Port == 445 {
			groupRes := map[string]string{}
			data1, _ := plugin_scan_ms17010.ScanMS17010(_item.IP, uint(t.params.TimeOutScanPortConnect))
			if len(data1) > 0 {
				dataStr, _ := json.Marshal(data1)
				_res := map[string]string{
					"type":     "MS17-010",
					"ip":       _item.IP,
					"port":     strconv.Itoa(int(_item.Port)),
					"protocol": _item.Item.Protocol,
					"vul_name": "MS17-010",
					"vul_info": string(dataStr),
				}
				_resByte, _ := json.Marshal(_res)
				groupRes["MS17-010"] = string(_resByte)
			} else {
				groupRes["MS17-010"] = ""
			}

			flag, _ := plugin_scan_smb_ghost.ScanSmbGhost(_item.IP, uint(t.params.TimeOutScanPortConnect))
			if flag {
				_res := map[string]string{
					"type":     "SMBGhost",
					"ip":       _item.IP,
					"port":     strconv.Itoa(int(_item.Port)),
					"protocol": _item.Item.Protocol,
					"vul_name": "SMBGhost",
					"vul_info": "",
				}
				_resByte, _ := json.Marshal(_res)
				groupRes["SMBGhost"] = string(_resByte)
			} else {
				groupRes["SMBGhost"] = ""
			}

			if groupRes["MS17-010"] != "" || groupRes["SMBGhost"] != "" {
				status = true
				groupRes["type"] = "group445"
				res = groupRes
			}
		}

		if status {
			tmpResult <- utils.CountResult{
				Count:  1,
				Result: res,
			}
		} else {
			tmpResult <- utils.CountResult{
				Count:  1,
				Result: nil,
			}
		}

	}(item)

	select {
	case res := <-tmpResult:
		result <- res
	case <-time.After(time.Duration(t.params.TimeOutScanPortConnect) * time.Second):
		//fmt.Println(fmt.Sprintf(`%s:%d timeout`, item.IP, item.Port))
		result <- utils.CountResult{
			Count:  1,
			Result: nil,
		}
	}

	<-worker

}

// 3.保存结果
func (t *taskScanVul) doDone(item interface{}, buf *bufio.Writer) (err error) {
	result := item.(map[string]string)

	if t.params.IsLog {
		switch result["type"] {
		case "group445":
			if result["MS17-010"] != "" {
				var record map[string]string
				err = json.Unmarshal([]byte(result["MS17-010"]), &record)
				if err != nil {
					return err
				}
				fmt.Println(fmt.Sprintf(`[+]发现MS17-010漏洞 %s:%s`, record["ip"], record["port"]))
			}

			if result["SMBGhost"] != "" {
				var record map[string]string
				err = json.Unmarshal([]byte(result["SMBGhost"]), &record)
				if err != nil {
					return err
				}
				fmt.Println(fmt.Sprintf(`[+]发现SMBGhost漏洞 %s:%s`, record["ip"], record["port"]))
			}
		case "网卡":
			var nets []string
			json.Unmarshal([]byte(result["content"]), &nets)
			for k, v := range nets {
				nets[k] = fmt.Sprintf("\t-> %s\r\n", v)
			}
			fmt.Println(
				fmt.Sprintf(
					"[+]发现网卡 %s:%s\r\n%s",
					result["ip"],
					result["port"],
					strings.Join(nets, ""),
				),
			)
		case "NetBIOS":
			fmt.Println(
				fmt.Sprintf(
					`[+]发现NetBIOS %s:%s <[Unique:%s] [Group:%s] [OSVersion:%s] [IsDC:%s]>`,
					result["ip"],
					result["port"],
					result["unique"],
					result["group"],
					result["os_version"],
					result["is_dc"],
				),
			)
		}
	}

	dataByte, _ := json.Marshal(result)
	buf.WriteString(string(dataByte) + "\n")

	return err
}

// 4.记录数量
func (t *taskScanVul) doAfter(data uint) {

}

// 执行并发探测系统高危漏洞
func DoTaskScanVul(req models.Params) {
	task := taskScanVul{params: req}

	totalTask := uint(len(req.WaitVul))
	totalTime := uint(math.Ceil(float64(totalTask)/float64(req.WorkerScanPort)) * float64(req.TimeOutScanPortConnect))

	utils.MultiTask(
		totalTask,
		uint(req.WorkerScanPort),
		totalTime,
		req.IsLog,
		task.doIter,
		task.doTask,
		task.doDone,
		task.doAfter,
		fmt.Sprintf(
			"开始系统高危漏洞+网卡识别+域控探测\r\n\r\n> 探测并发：%d\r\n> 探测超时：%d\r\n> 目标端口：135,139,445\r\n",
			req.WorkerScanPort,
			req.TimeOutScanPortConnect,
		),
		"完成系统高危漏洞+网卡识别+域控探测",
		"vul.txt",
		func() {},
		req.WaitVul,
	)

}
