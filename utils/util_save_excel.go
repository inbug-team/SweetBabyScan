package utils

import (
	"fmt"
	"github.com/xuri/excelize/v2"
	"io/ioutil"
)

func InitExcel(filename string, data []byte) {
	ioutil.WriteFile(filename, data, 0777)
}

func SaveData(filename, sheet string, data map[string]interface{}) {
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

	for key, val := range data {
		f.SetCellValue(sheet, key, val)
	}

	f.Save()
}
