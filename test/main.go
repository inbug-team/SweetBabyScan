package main

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/config"
	"github.com/xuri/excelize/v2"
	"io/ioutil"
)

func main() {
	filename := "./result.xlsx"
	ioutil.WriteFile(filename, config.TmpExcel, 0777)
	f, err := excelize.OpenFile(filename)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Println(err)
		}
	}()

	err = f.SetCellValue("存活IP", "A2", "192.168.188.1")
	fmt.Println(err)
	err = f.SetCellValue("存活IP", "A3", "192.168.188.2")
	fmt.Println(err)
	err = f.SetCellValue("存活IP", "A4", "192.168.188.3")
	fmt.Println(err)
	err = f.Save()
	fmt.Println(err)
}
