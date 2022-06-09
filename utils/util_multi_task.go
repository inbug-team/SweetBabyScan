package utils

import (
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/inbug-team/SweetBabyScan/models"
	"runtime"
	"sync"
	"time"
)

type CountResult struct {
	Count  uint
	Result interface{}
}

type Task func(*sync.WaitGroup, chan bool, chan CountResult, ...interface{})
type Iter func(*sync.WaitGroup, chan bool, chan CountResult, Task, ...interface{})
type Done func(interface{}) error
type Ing func(float32)
type After func(uint)
type PrintResult func()

func StaticLeftTime(t float32) string {
	if t < models.M {
		return fmt.Sprintf(`%.2fsec`, t)
	} else if t > models.M && t < models.H {
		return fmt.Sprintf(`%.2fmin`, t/models.M)
	} else {
		return fmt.Sprintf(`%.2fhour`, t/models.H)
	}
}

func MultiTask(
	totalTask, workerNumber, totalTime uint,
	iter Iter,
	task Task,
	done Done,
	after After,
	msgStart, msgEnd string,
	printResult PrintResult,
	data ...interface{},
) float32 {
	runtime.GOMAXPROCS(runtime.NumCPU())

	var _time float32 = 0.0
	if totalTask == 0 {
		return _time
	}

	fmt.Println("****************<-START->****************")
	fmt.Println(msgStart)

	tmpl := `{{string . "alive" | yellow}} {{counters . | red}} {{ bar . "[" "=" (cycle . "↖" "↗" "↘" "↙" ) "." "]"}} {{percent . | green}} {{speed . | blue}} {{string . "leftTime" | red}} `

	bar := pb.ProgressBarTemplate(tmpl).Start(int(totalTask))
	start := time.Now()
	if totalTask <= workerNumber {
		workerNumber = totalTask
	}
	var wg sync.WaitGroup
	worker := make(chan bool, workerNumber)
	result := make(chan CountResult, workerNumber)
	var ingTask, doneTask uint = 0, 0
	bar.Set("alive", "[+](0)")
	go func() {
		iter(&wg, worker, result, task, data...)
		wg.Wait()
		close(worker)
	}()

	for {
		select {
		case item := <-result:
			// 获取计数
			number := item.Count
			// 获取记录
			newItem := item.Result
			// 记录进度
			ingTask += number
			bar.Add(int(number))
			// 保存数据
			if newItem != nil {
				if err := done(newItem); err == nil {
					doneTask++
					bar.Set("alive", fmt.Sprintf("[+](%d)", doneTask))
				}
			}
			leftTime := (1 - float32(ingTask)/float32(totalTask)) * float32(totalTime)
			bar.Set("leftTime", fmt.Sprintf("LeftTime: %s", StaticLeftTime(leftTime)))
			// 完成计数
			if ingTask == totalTask {
				bar.Set("leftTime", "")
				after(doneTask)
				goto Loop
			}
		default:
			continue
		}
	}
Loop:
	bar.Finish()
	_time = float32(time.Since(start).Seconds())
	printResult()
	fmt.Println(fmt.Sprintf(`%s，执行总耗时：%f秒`, msgEnd, _time))
	fmt.Print("*****************<-END->*****************" + "\r\n\r\n")
	return _time
}
