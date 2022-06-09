package task_scan_weak

import (
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/inbug-team/SweetBabyScan/config"
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
var saveTxt = []string{"*****************<User Password>*****************\r\n"}
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
	passList := utils.RemoveRepeatedElement(up["pass"])
	userList := utils.RemoveRepeatedElement(up["user"])

	if len(passList) != 0 && len(userList) == 0 {
		userList = []string{""}
	}

	totalTask := uint(len(passList) * len(userList))
	var ingTask uint = 0

	tmpl := `{{string . "alive" | yellow}} {{counters . | red}} {{ bar . "[" "=" (cycle . "↖" "↗" "↘" "↙" ) "." "]"}} {{percent . | green}} {{speed . | blue}} {{string . "result" | magenta}}`
	bar := pb.ProgressBarTemplate(tmpl).Start(int(totalTask))
	bar.Set("alive", fmt.Sprintf("%s:%s<%s>[+](0)", item.Ip, item.Port, item.Service))

	var wg sync.WaitGroup
	workerNumber := uint(config.WorkerMap[key])
	if totalTask <= workerNumber {
		workerNumber = totalTask
	}
	worker := make(chan bool, workerNumber)
	workerResult := make(chan utils.CountResult, workerNumber)

	go func() {
		for _, user := range userList {
			for _, pass := range passList {
				wg.Add(1)
				worker <- true
				go func(_wg *sync.WaitGroup, _user, _pass string, _item models.WaitScanWeak) {
					defer _wg.Done()

					port, _ := strconv.Atoi(_item.Port)
					_port := uint(port)
					tmpResult := make(chan utils.CountResult, 1)

					go func(_key, __user, __pass string, __item models.WaitScanWeak, __port uint) {
						status := false
						if _key == "redis" {
							status = plugin_scan_weak.CheckRedis(__item.Ip, __user, __pass, __port)
						} else if _key == "ssh" {
							status = plugin_scan_weak.CheckSSH(__item.Ip, __user, __pass, __port)
						} else if _key == "mongodb" {
							status = plugin_scan_weak.CheckMongoDB(__item.Ip, __user, __pass, __port)
						} else if _key == "mysql" {
							status = plugin_scan_weak.CheckRDB("mysql", __item.Ip, __user, __pass, __port)
						} else if _key == "postgres" {
							status = plugin_scan_weak.CheckRDB("postgres", __item.Ip, __user, __pass, __port)
						} else if _key == "sqlserver" {
							status = plugin_scan_weak.CheckRDB("mssql", __item.Ip, __user, __pass, __port)
						} else if _key == "ftp" {
							status = plugin_scan_weak.CheckFTP(__item.Ip, __user, __pass, __port)
						} else if _key == "elasticsearch" {
							status = plugin_scan_weak.CheckElasticSearch(__item.Ip, __user, __pass, __port)
						} else if _key == "smb" {
							status = plugin_scan_weak.CheckSMB(__item.Ip, __user, __pass, __port)
						} else if _key == "snmp" {
							status = plugin_scan_weak.CheckSNMP(__item.Ip, __pass, __port)
						}

						if status {
							tmpResult <- utils.CountResult{
								Count: 1,
								Result: models.ScanWeak{
									Ip:       __item.Ip,
									Port:     __item.Port,
									Service:  __item.Service,
									Probe:    __item.Probe,
									Protocol: __item.Protocol,
									User:     __user,
									Pass:     __pass,
								},
							}
						} else {
							tmpResult <- utils.CountResult{
								Count:  1,
								Result: nil,
							}
						}
					}(key, _user, _pass, _item, _port)

					select {
					case res := <-tmpResult:
						workerResult <- res
					case <-time.After(time.Duration(req.TimeOutScanWeak) * time.Second):
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

				saveTxt = append(
					saveTxt,
					fmt.Sprintf(
						"%s:%s [%s] <[user:%s] [pass:%s]>",
						result.Ip,
						result.Port,
						result.Service,
						result.User,
						result.Pass,
					)+"\r\n",
				)
				index++

				bar.Set("alive", fmt.Sprintf("%s:%s<%s>[+](1)", item.Ip, item.Port, item.Service))
				bar.Set("result", fmt.Sprintf("<[user:%s] [pass:%s]>", result.User, result.Pass))
				bar.Add(int(totalTask - ingTask))
				bar.Finish()

				lock.Unlock()
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
	if len(req.WaitWeak) == 0 {
		return
	}

	fmt.Println("****************<-START->****************")

	service := req.ServiceScanWeak
	if service == "" {
		service = config.Service
	}

	fmt.Println(fmt.Sprintf(
		"开始弱口令爆破\r\n\r\n> 爆破协议：%s\r\n> 爆破并发：%s\r\n> 爆破分组：%d\r\n",
		service,
		req.WorkerScanWeak,
		req.GroupScanWeak,
	))

	var _time float32 = 0.0
	start := time.Now()

	var wg sync.WaitGroup

	groupScanWeak := req.GroupScanWeak
	if len(req.WaitWeak) < groupScanWeak {
		groupScanWeak = len(req.WaitWeak)
	}
	workerGroup := make(chan bool, req.GroupScanWeak)

	for _, item := range req.WaitWeak {
		taskScanWeakGroup(req, item, &wg, workerGroup, item.Service)
	}

	wg.Wait()
	close(workerGroup)

	saveTxt = append(saveTxt, "*****************<User Password>*****************\r\n\r\n")
	// 保存数据
	utils.SaveData(req.OutputExcel, "弱口令", saveData)
	utils.SaveText(req.OutputTxt, saveTxt)

	_time = float32(time.Since(start).Seconds())
	fmt.Println(fmt.Sprintf(`完成弱口令爆破，执行总耗时：%f秒`, _time))
	fmt.Println("*****************<-END->*****************")
}
