package task_scan_poc_nuclei

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_nuclei"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_site"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"sync"
	"time"
)

type taskScanPocNuclei struct {
	params models.Params
}

var pocData []models.ScanPoc
var index = 2
var savePocs = map[string]interface{}{}
var savePocTxt = []string{"*****************<Poc Nuclei>*****************\r\n"}

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
	tmpResult := make(chan utils.CountResult, 1)

	go func(_item models.ScanSite, _poc models.DataPocNuclei) {
		_link := _item.Link
		if _item.LinkRedirect != "" {
			_link = plugin_scan_site.GetUrl(_item.LinkRedirect)
		}
		isVul, packetSend, packetRecv, err := plugin_scan_poc_nuclei.ScanPocNuclei(_link, &_poc)
		if err == nil && isVul {
			tmpResult <- utils.CountResult{
				Count: 1,
				Result: models.ScanPoc{
					Url:         _item.Link,
					Host:        _item.Host,
					Port:        _item.Port,
					Title:       _item.Title,
					Keywords:    _item.Keywords,
					Description: _item.Description,
					StatusCode:  _item.StatusCode,
					PacketSend:  packetSend,
					PacketRecv:  packetRecv,
					PocName:     _poc.PocName,
					VulName:     _poc.Template.Info.Name,
					VulDesc:     _poc.Template.Info.Description,
					VulLevel:    _poc.VulLevel,
					PocProtocol: _poc.PocProtocol,
					PocCatalog:  _poc.PocCatalog,
					CmsName:     _item.CmsName,
				},
			}
		} else {
			tmpResult <- utils.CountResult{
				Count:  1,
				Result: nil,
			}
		}
	}(item, poc)

	select {
	case res := <-tmpResult:
		result <- res
	case <-time.After(time.Duration(t.params.TimeOutScanPocNuclei) * time.Second):
		result <- utils.CountResult{
			Count:  1,
			Result: nil,
		}
	}
	<-worker
}

// 3.保存结果
func (t *taskScanPocNuclei) doDone(item interface{}) error {
	result := item.(models.ScanPoc)
	pocData = append(pocData, result)

	savePocs[fmt.Sprintf("A%d", index)] = result.Host
	savePocs[fmt.Sprintf("B%d", index)] = "nuclei"
	savePocs[fmt.Sprintf("C%d", index)] = result.Url
	savePocs[fmt.Sprintf("D%d", index)] = result.VulName
	savePocs[fmt.Sprintf("E%d", index)] = result.VulLevel
	savePocs[fmt.Sprintf("F%d", index)] = result.VulDesc
	savePocs[fmt.Sprintf("G%d", index)] = result.PocName
	savePocs[fmt.Sprintf("H%d", index)] = result.PacketSend
	savePocs[fmt.Sprintf("I%d", index)] = result.PacketRecv

	savePocTxt = append(savePocTxt, fmt.Sprintf(
		"%s <[Title:%s] [Name:%s] [Level:%s] [CataLog:%s]>",
		result.Url,
		result.Title,
		result.PocName,
		result.VulLevel,
		result.PocCatalog,
	)+"\r\n")

	index++

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
func DoTaskScanPocNuclei(req models.Params) int {
	task := taskScanPocNuclei{params: req}

	totalTask := uint(len(req.PocNuclei)) * uint(len(req.Sites))
	totalTime := uint(math.Ceil(float64(totalTask)/float64(req.WorkerScanPoc)) * float64(req.TimeOutScanPocNuclei))

	utils.MultiTask(
		totalTask,
		uint(req.WorkerScanPoc),
		totalTime,
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
		func() {
			savePocTxt = append(savePocTxt, "*****************<Poc Nuclei>*****************\r\n\r\n")
			// 保存数据-漏洞信息
			utils.SaveData(req.OutputExcel, "漏洞信息", savePocs)
			utils.SaveText(req.OutputTxt, savePocTxt)
		},
		req.Sites,
		req.PocNuclei,
	)

	return index
}
