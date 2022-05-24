package utils

import (
	"SweetBabyScan/models"
	"bufio"
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"os"
	"sync"
	"time"
)

type CountResult struct {
	Count  uint
	Result interface{}
}

type Task func(*sync.WaitGroup, chan bool, chan CountResult, ...interface{})
type Iter func(*sync.WaitGroup, chan bool, chan CountResult, Task, ...interface{})
type Done func(interface{}, *bufio.Writer) error
type Ing func(float32)
type After func(uint)

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
	isLog bool,
	iter Iter,
	task Task,
	done Done,
	after After,
	msgStart, msgEnd, filename string,
	data ...interface{},
) float32 {
	var _time float32 = 0.0
	if totalTask == 0 {
		return _time
	}

	// O_TRUNC 清空重写
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0777)
	if err != nil {
		return _time
	}
	defer file.Close()

	buf := bufio.NewWriter(file)

	fmt.Println("****************<-START->****************")
	fmt.Println(msgStart)

	tmpl := `{{string . "alive" | yellow}} {{counters . | red}} {{ bar . "[" "=" (cycle . "↖" "↗" "↘" "↙" ) "." "]"}} {{percent . | green}} {{speed . | blue}} {{string . "leftTime" | red}}`
	if isLog {
		tmpl += `
`
	}
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
				if err := done(newItem, buf); err == nil {
					doneTask++
					bar.Set("alive", fmt.Sprintf("[+](%d)", doneTask))
				}
			}
			leftTime := (1 - float32(ingTask)/float32(totalTask)) * float32(totalTime)
			bar.Set("leftTime", fmt.Sprintf("LeftTime: %s", StaticLeftTime(leftTime)))
			// 完成计数
			if ingTask == totalTask {
				after(doneTask)
				goto Loop
			}
		default:
			continue
		}
	}
Loop:
	bar.Finish()
	buf.Flush()
	_time = float32(time.Since(start).Seconds())
	fmt.Println(fmt.Sprintf(`%s，执行总耗时：%f秒`, msgEnd, _time))
	fmt.Println("****************<-END->****************")
	return _time
}
