package task_scan_site

import (
	"encoding/json"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_site"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"strconv"
	"strings"
	"sync"
)

type taskScanSite struct {
	params models.Params
}

var sites []models.ScanSite
var index = 2
var saveWeb = map[string]interface{}{}
var saveWebTxt = []string{"*****************<WEB>*****************\r\n"}

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
	site = plugin_scan_site.DoScanSite(item, t.params.FileDate, t.params.TimeOutScanSite, t.params.TimeOutScreen, t.params.IsScreen)
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
func (t *taskScanSite) doDone(item interface{}) error {
	result := item.(models.ScanSite)

	sites = append(sites, result)
	saveWeb[fmt.Sprintf("A%d", index)] = result.Host
	saveWeb[fmt.Sprintf("B%d", index)], _ = strconv.Atoi(result.Port)
	if strings.HasPrefix(result.Link, "https") {
		saveWeb[fmt.Sprintf("C%d", index)] = "https"
	} else {
		saveWeb[fmt.Sprintf("C%d", index)] = "http"
	}
	saveWeb[fmt.Sprintf("D%d", index)] = result.Link
	saveWeb[fmt.Sprintf("E%d", index)] = result.Title

	var cmsInfo []string
	json.Unmarshal([]byte(result.CmsInfo), &cmsInfo)
	cmsName := strings.Join(cmsInfo, "|")
	if cmsName == "" {
		cmsName = result.CmsName
	}

	saveWeb[fmt.Sprintf("F%d", index)] = cmsName
	saveWeb[fmt.Sprintf("G%d", index)] = result.StatusCode
	saveWeb[fmt.Sprintf("H%d", index)] = "." + result.Image
	index++

	saveWebTxt = append(
		saveWebTxt,
		fmt.Sprintf(
			`%s <[Title:%s] [Code:%s] [Finger:%s]>`,
			result.Link,
			result.Title,
			result.StatusCode,
			cmsName)+"\r\n",
	)
	if result.LinkRedirect != "" {
		saveWebTxt = append(
			saveWebTxt,
			fmt.Sprintf(
				"\t|--> Redirect %s",
				result.LinkRedirect,
			)+"\r\n",
		)
	}

	if t.params.IsLog {
		fmt.Println(fmt.Sprintf(`[+]发现网站 %s <[Title:%s] [Code:%s] [Finger:%s]>`, result.Link, result.Title, result.StatusCode, cmsName))
		if result.LinkRedirect != "" {
			fmt.Println(fmt.Sprintf("[>]跳转链接 %s", result.LinkRedirect))
		}
	}
	return nil
}

// 4.记录数量
func (t *taskScanSite) doAfter(data uint) {

}

// 执行并发爬虫
func DoTaskScanSite(req models.Params) []models.ScanSite {
	// 修改状态
	task := taskScanSite{params: req}

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
		func() {
			saveWebTxt = append(saveWebTxt, "*****************<WEB>*****************\r\n\r\n")

			// 保存数据-WEB信息
			utils.SaveData(req.OutputExcel, "WEB", saveWeb)
			utils.SaveText(req.OutputTxt, saveWebTxt)
		},
		req.Urls,
	)

	return sites
}
