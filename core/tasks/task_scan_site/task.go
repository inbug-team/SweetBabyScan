package task_scan_site

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_site"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"sync"
)

type taskScanSite struct {
	req models.Params
}

var sites []models.ScanSite

// 1.迭代方法
func (t *taskScanSite) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	items := data[0]
	for _, item := range items.([]string) {
		wg.Add(1)
		worker <- true
		go task(wg, worker, result, item)
	}
}

// 2.任务方法
func (t *taskScanSite) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	item := data[0].(string)
	status := false
	var site models.ScanSite
	site = plugin_scan_site.DoScanSite(item, "", 0, t.req.TimeOutScanSite, t.req.TimeOutScreen, t.req.IsScreen)
	if site.StatusCode != "" {
		status = true
	}

	if status {
		result <- utils.CountResult{
			Count:  1,
			Result: site,
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
func (t *taskScanSite) doDone(item interface{}, buf *bufio.Writer) error {
	result := item.(models.ScanSite)

	sites = append(sites, result)

	dataByte, _ := json.Marshal(result)
	buf.WriteString(string(dataByte) + "\n")

	if t.req.IsLog {
		fmt.Println(fmt.Sprintf(`[+]发现网站 %s <[Title:%s] [Code:%s] [Finger:%s]>`, result.Link, result.Title, result.StatusCode, result.CmsName))
	}
	return nil
}

// 4.记录数量
func (t *taskScanSite) doAfter(data uint) {

}

// 执行并发爬虫
func DoTaskScanSite(req models.Params) []models.ScanSite {
	// 修改状态
	task := taskScanSite{req: req}

	totalTask := uint(len(req.Urls))
	var totalTime uint = 0
	batch := math.Ceil(float64(totalTask) / float64(req.WorkerScanSite))
	if req.IsScreen {
		totalTime = uint(batch * float64(req.TimeOutScreen+req.TimeOutScanSite))
	} else {
		totalTime = uint(batch * float64(req.TimeOutScanSite))
	}

	// 执行任务
	utils.MultiTask(
		totalTask,
		uint(req.WorkerScanSite),
		totalTime,
		req.IsLog,
		task.doIter,
		task.doTask,
		task.doDone,
		task.doAfter,
		fmt.Sprintf(
			"开始扫描网站CMS\r\n\r\n> 爬虫并发：%d\r\n> 爬虫超时：%d\r\n> 截图超时：%d\r\n> 是否截图：%t\r\n",
			req.WorkerScanSite,
			req.TimeOutScanSite,
			req.TimeOutScreen,
			req.IsScreen,
		),
		"完成扫描网站CMS",
		"site.txt",
		req.Urls,
	)

	return sites
}
