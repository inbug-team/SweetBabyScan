package task_scan_poc_xray

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/config"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_xray"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"net/http"
	"sync"
)

type taskScanPocXray struct {
	params models.Params
}

var pocData []models.ScanPoc
var index = 2
var savePocs = map[string]interface{}{}

// 1.迭代方法
func (t *taskScanPocXray) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	items, pocArr := data[0], data[1]
	for _, item := range items.([]models.ScanSite) {
		for _, poc := range pocArr.([]models.DataPocXray) {
			wg.Add(1)
			worker <- true
			go task(wg, worker, result, item, poc)
		}
	}
}

// 2.任务方法
func (t *taskScanPocXray) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	item, poc := data[0].(models.ScanSite), data[1].(models.DataPocXray)
	if item.Link != "" {
		oReq, _ := http.NewRequest("GET", item.Link, nil)
		oReq.Header.Set("User-agent", config.GetUserAgent())

		isVul, err, _ := plugin_scan_poc_xray.ScanPocXray(oReq, &poc)
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
					PacketSend:  "",
					PacketRecv:  "",
					PocName:     poc.Name,
					VulName:     "",
					VulDesc:     poc.Detail.Description,
					VulLevel:    "",
					PocProtocol: "",
					PocCatalog:  "",
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
func (t *taskScanPocXray) doDone(item interface{}) error {
	result := item.(models.ScanPoc)
	pocData = append(pocData, result)

	savePocs[fmt.Sprintf("A%d", index)] = result.Ip
	savePocs[fmt.Sprintf("B%d", index)] = "xray"
	savePocs[fmt.Sprintf("C%d", index)] = result.Url
	savePocs[fmt.Sprintf("D%d", index)] = result.PocName
	savePocs[fmt.Sprintf("E%d", index)] = result.VulLevel
	savePocs[fmt.Sprintf("F%d", index)] = result.VulDesc
	savePocs[fmt.Sprintf("G%d", index)] = result.PocName
	index++

	if t.params.IsLog {
		fmt.Println(
			fmt.Sprintf(
				"[+][PocXray]发现web漏洞 %s <[Title:%s] [Name:%s]>",
				result.Url,
				result.Title,
				result.PocName,
			),
		)
	}

	return nil
}

// 4.记录数量
func (t *taskScanPocXray) doAfter(data uint) {

}

// 执行Poc漏洞扫描
func DoTaskScanPocXray(req models.Params, i int) {
	index = i
	task := taskScanPocXray{params: req}

	totalTask := uint(len(req.PocXray)) * uint(len(req.Sites))
	totalTime := uint(math.Ceil(float64(totalTask)/float64(req.WorkerScanPoc)) * float64(10))

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
			"开始PocXray漏洞检测\r\n\r\n> Poc并发：%d\r\n> 筛选Poc名称：%s\r\n> Poc扫描超时：%d\r\n",
			req.WorkerScanPoc,
			req.FilterPocName,
			10,
		),
		"完成PocXray漏洞检测",
		func() {
			// 保存数据-漏洞信息
			utils.SaveData(req.SaveFile, "漏洞信息", savePocs)
		},
		req.Sites,
		req.PocXray,
	)
}
