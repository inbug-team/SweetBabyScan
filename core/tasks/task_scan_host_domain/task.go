package task_scan_host_domain

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_host"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"math"
	"sync"
)

type taskScanHostDomain struct {
	params models.Params
}

var domain []string

// 1.迭代方法
func (t *taskScanHostDomain) doIter(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, task utils.Task, data ...interface{}) {
	items := data[0]
	for _, item := range items.([]string) {
		wg.Add(1)
		worker <- true
		go task(wg, worker, result, item)
	}
}

// 2.任务方法
func (t *taskScanHostDomain) doTask(wg *sync.WaitGroup, worker chan bool, result chan utils.CountResult, data ...interface{}) {
	defer wg.Done()
	item := data[0].(string)
	status := plugin_scan_host.ScanHostByPing(item)
	if status {
		result <- utils.CountResult{
			Count:  1,
			Result: item,
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
func (t *taskScanHostDomain) doDone(item interface{}) error {
	result := item.(string)
	domain = append(domain, result)

	if t.params.IsLog {
		fmt.Println(fmt.Sprintf("[+]发现存活域名 %s", result))
	}

	return nil
}

// 4.记录数量
func (t *taskScanHostDomain) doAfter(data uint) {

}

// 执行并发存活检测
func DoTaskScanHostDomain(req models.Params, index int) []string {
	task := taskScanHostDomain{params: req}

	totalTask := uint(len(req.Domains))
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
			"开始域名主机存活检测\r\n\r\n> 存活并发：%d\r\n> 存活超时：%d\r\n> 检测方式：%s\r\n> 检测域名：%s\r\n",
			req.WorkerScanHost,
			req.TimeOutScanHost,
			"PING",
			req.Domain,
		),
		"完成域名主机存活检测",
		func() {
			// 保存数据-存活域名
			saveDomains := map[string]interface{}{}
			saveDomainTxt := []string{"*****************<Domain>*****************\r\n"}
			indexDomains := index
			for _, v := range domain {
				saveDomains[fmt.Sprintf("A%d", indexDomains)] = v
				saveDomainTxt = append(saveDomainTxt, fmt.Sprintf("%s\r\n", v))
				indexDomains++
			}
			saveDomainTxt = append(saveDomainTxt, "*****************<Domain>*****************\r\n\n")

			utils.SaveData(req.OutputExcel, "存活主机", saveDomains)
			utils.SaveText(req.OutputTxt, saveDomainTxt)

		},
		req.Domains,
	)
	return domain
}
