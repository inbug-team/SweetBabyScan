package task_scan_weak

import (
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_weak"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"strconv"
	"strings"
	"sync"
	"time"
)

var index = 2
var saveData = map[string]interface{}{}
var lock sync.Mutex

// 爆破分组
func taskScanWeakGroup(req models.Params, item models.WaitScanWeak, wg *sync.WaitGroup, workerGroup chan bool, key string) {
	wg.Add(1)
	workerGroup <- true
	go func(_wg *sync.WaitGroup, _item models.WaitScanWeak) {
		defer _wg.Done()
		taskScanWeak(req, _item, key)
		<-workerGroup
	}(wg, item)
}

// 爆破
func taskScanWeak(req models.Params, item models.WaitScanWeak, key string) {
	up := req.UserPass[key]
	passList := up["pass"]
	userList := up["user"]

	if len(passList) != 0 && len(userList) == 0 {
		userList = []string{""}
	}

	totalTask := uint(len(passList) * len(userList))
	var ingTask uint = 0

	tmpl := `{{string . "alive" | yellow}} {{counters . | red}} {{ bar . "[" "=" (cycle . "↖" "↗" "↘" "↙" ) "." "]"}} {{percent . | green}} {{speed . | blue}}`
	if req.IsLog {
		tmpl += `
`
	}
	bar := pb.ProgressBarTemplate(tmpl).Start(int(totalTask))
	bar.Set("alive", fmt.Sprintf("%s:%s<%s>[+](0)", item.Ip, item.Port, item.Service))

	var wg sync.WaitGroup
	workerNumber := uint(req.WorkerScanWeak)
	if totalTask <= workerNumber {
		workerNumber = totalTask
	}
	worker := make(chan bool, totalTask)
	workerResult := make(chan utils.CountResult, workerNumber)

	go func() {
		for _, user := range userList {
			for _, pass := range passList {
				wg.Add(1)
				worker <- true
				go func(_wg *sync.WaitGroup, _user, _pass string, _item models.WaitScanWeak) {
					defer _wg.Done()
					status := false
					port, _ := strconv.Atoi(_item.Port)
					_port := uint(port)
					if key == "redis" {
						status = plugin_scan_weak.CheckRedis(_item.Ip, _user, _pass, _port)
					} else if key == "ssh" {
						status = plugin_scan_weak.CheckSSH(_item.Ip, _user, _pass, _port)
					} else if key == "mongodb" {
						status = plugin_scan_weak.CheckMongoDB(_item.Ip, _user, _pass, _port)
					} else if key == "mysql" {
						status = plugin_scan_weak.CheckRDB("mysql", _item.Ip, _user, _pass, _port)
					} else if key == "postgres" {
						status = plugin_scan_weak.CheckRDB("postgres", _item.Ip, _user, _pass, _port)
					} else if key == "sqlserver" {
						status = plugin_scan_weak.CheckRDB("mssql", _item.Ip, _user, _pass, _port)
					} else if key == "ftp" {
						status = plugin_scan_weak.CheckFTP(_item.Ip, _user, _pass, _port)
					} else if key == "elasticsearch" {
						status = plugin_scan_weak.CheckElasticSearch(_item.Ip, _user, _pass, _port)
					} else if key == "smb" {
						status = plugin_scan_weak.CheckSMB(_item.Ip, _user, _pass, _port)
					} else if key == "snmp" {
						status = plugin_scan_weak.CheckSNMP(_item.Ip, _pass, _port)
					}

					if status {
						workerResult <- utils.CountResult{
							Count: 1,
							Result: models.ScanWeak{
								Ip:       _item.Ip,
								Port:     _item.Port,
								Service:  _item.Service,
								Probe:    _item.Probe,
								Protocol: _item.Protocol,
								User:     _user,
								Pass:     _pass,
							},
						}
					} else {
						workerResult <- utils.CountResult{
							Count:  1,
							Result: nil,
						}
					}
					<-worker

				}(&wg, user, strings.ReplaceAll(pass, "%user%", user), item)
			}
		}
		wg.Wait()
		close(worker)
	}()

	for {
		select {
		case res := <-workerResult:
			// 记录爆破进度
			ingTask += res.Count

			bar.Add(int(res.Count))

			// 保存爆破记录
			if res.Result != nil {
				result := res.Result.(models.ScanWeak)

				lock.Lock()
				saveData[fmt.Sprintf(`A%d`, index)] = result.Ip
				saveData[fmt.Sprintf(`B%d`, index)], _ = strconv.Atoi(result.Port)
				saveData[fmt.Sprintf(`C%d`, index)] = result.Service
				saveData[fmt.Sprintf(`D%d`, index)] = result.User
				saveData[fmt.Sprintf(`E%d`, index)] = result.Pass
				index++
				lock.Unlock()

				if req.IsLog {
					fmt.Println(fmt.Sprintf(
						`[%s:%s|%s|%s|%s] 爆破成功，账号：%s|密码：%s`,
						result.Ip,
						result.Port,
						result.Protocol,
						result.Service,
						result.Probe,
						result.User,
						result.Pass,
					))
				}
				bar.Set("alive", fmt.Sprintf("%s:%s<%s>[+](1)", item.Ip, item.Port, item.Service))
				bar.Add(int(totalTask - ingTask))
				bar.Finish()
				return
			}

			if ingTask == totalTask {
				bar.Finish()
				return
			}

		default:
			time.Sleep(1 * time.Second)
		}
	}

}

func DoTaskScanWeak(req models.Params) {
	fmt.Println("****************<-START->****************")
	fmt.Println(fmt.Sprintf(
		"开始弱口令爆破\r\n\r\n> 爆破并发：%d\r\n> 爆破分组：%d\r\n",
		req.WorkerScanWeak,
		req.GroupScanWeak,
	))

	var _time float32 = 0.0
	start := time.Now()

	var wg sync.WaitGroup
	workerGroup := make(chan bool, req.GroupScanWeak)
	for _, item := range req.WaitWeak {
		taskScanWeakGroup(req, item, &wg, workerGroup, item.Service)
	}

	wg.Wait()
	close(workerGroup)

	// 保存数据
	utils.SaveData(req.SaveFile, "弱口令", saveData)

	_time = float32(time.Since(start).Seconds())
	fmt.Println(fmt.Sprintf(`完成弱口令爆破，执行总耗时：%f秒`, _time))
	fmt.Println("*****************<-END->*****************")
}
