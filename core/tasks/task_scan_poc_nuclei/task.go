package task_scan_poc_nuclei

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_nuclei"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"sync"
)

type taskScanPocNuclei struct {
	params models.Params
}

var pocData []models.ScanPoc

// 1.迭代方法
func (t *taskScanPocNuclei) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	items, pocArr := data[0], data[1]
	for _, item := range items.([]models.ScanSite) {
		for _, poc := range pocArr.([]models.DataPocNuclei) {
			wg.Add(1)
			worker <- true
			go task(wg, worker, result, item, poc)
		}
	}
}

// 2.任务方法
func (t *taskScanPocNuclei) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	item, poc := data[0].(models.ScanSite), data[1].(models.DataPocNuclei)
	if item.Link != "" {
		isVul, packetSend, packetRecv, err := plugin_scan_poc_nuclei.ScanPocNuclei(item.Link, &poc)
		if err == nil && isVul {
			result <- utils.CountResult{
				Count: 1,
				Result: models.ScanPoc{
					Url:         item.Link,
					Ip:          item.Ip,
					Port:        item.Port,
					Title:       item.Title,
					Keywords:    item.Keywords,
					Description: item.Description,
					StatusCode:  item.StatusCode,
					PacketSend:  packetSend,
					PacketRecv:  packetRecv,
					PocName:     poc.PocName,
					VulLevel:    poc.VulLevel,
					PocProtocol: poc.PocProtocol,
					PocCatalog:  poc.PocCatalog,
					CmsName:     item.CmsName,
				},
			}
		} else {
			result <- utils.CountResult{
				Count:  1,
				Result: nil,
			}
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
func (t *taskScanPocNuclei) doDone(item interface{}, buf *bufio.Writer) error {
	result := item.(models.ScanPoc)
	pocData = append(pocData, result)

	dataByte, _ := json.Marshal(result)
	buf.WriteString(string(dataByte) + "\n")

	if t.params.IsLog {
		fmt.Println(
			fmt.Sprintf(
				"[+][PocNuclei]发现web漏洞 %s <[Title:%s] [Name:%s] [Level:%s] [CataLog:%s]>",
				result.Url,
				result.Title,
				result.PocName,
				result.VulLevel,
				result.PocCatalog,
			),
		)
	}

	return nil
}

// 4.记录数量
func (t *taskScanPocNuclei) doAfter(data uint) {

}

// 执行Poc漏洞扫描
func DoTaskScanPocNuclei(req models.Params) {
	task := taskScanPocNuclei{params: req}

	totalTask := uint(len(req.Pocs)) * uint(len(req.Sites))
	totalTime := uint(math.Ceil(float64(totalTask)/float64(req.WorkerScanPoc)) * float64(req.TimeOutScanPocNuclei))

	utils.MultiTask(
		totalTask,
		uint(req.WorkerScanPoc),
		totalTime,
		req.IsLog,
		task.doIter,
		task.doTask,
		task.doDone,
		task.doAfter,
		fmt.Sprintf(
			"开始PocNuclei漏洞检测\r\n\r\n> Poc并发：%d\r\n> 筛选Poc名称：%s\r\n> 筛选Poc等级：%s\r\n> Poc扫描超时：%d\r\n",
			req.WorkerScanPoc,
			req.FilterPocName,
			req.FilterVulLevel,
			req.TimeOutScanPocNuclei,
		),
		"完成PocNuclei漏洞检测",
		"poc-nuclei.txt",
		func() {},
		req.Sites,
		req.Pocs,
	)
}
