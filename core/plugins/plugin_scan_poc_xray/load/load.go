package load

import (
	"embed"
	"errors"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/jedib0t/go-pretty/v6/table"
	"gopkg.in/yaml.v3"
	"io/fs"
	"path/filepath"
)

// 解析Poc Xray到表格
func ParsePocXrayToTable(items []models.DataPocXray) (rows []table.Row) {
	ID := 1
	for _, poc := range items {
		rows = append(rows, table.Row{ID, poc.Name, poc.Detail.Description})
		ID++
	}
	return
}

// 过滤 Poc Xray [表格形式]
func FilterPocXrayTable(arr []table.Row, fn func(pocName string, params models.Params) bool, p models.Params) (result []table.Row, total int) {
	for _, item := range arr {
		if fn(item[1].(string), p) {
			result = append(result, item)
		}
	}
	return result, len(result)
}

// 过滤 Poc Xray
func FilterPocXrayData(arr []models.DataPocXray, fn func(pocName string, params models.Params) bool, p models.Params) (result []models.DataPocXray, total int) {
	for _, item := range arr {
		if fn(item.Name, p) {
			result = append(result, item)
		}
	}
	return result, len(result)
}

// 加载POC
func ParsePocXrayData(data []byte) (poc models.DataPocXray, err error) {
	err = yaml.Unmarshal(data, &poc)
	if err != nil {
		return poc, err
	}

	if poc.Name == "" {
		return poc, errors.New("poc name is empty")
	}

	return poc, nil
}

// 解析所有Poc Xray文件
func ParsePocXrayFiles(dirXrayPoc embed.FS) (items []models.DataPocXray) {
	err := fs.WalkDir(dirXrayPoc, ".", func(path string, info fs.DirEntry, err error) error {
		if filepath.Ext(path) == ".yml" {
			content, err := dirXrayPoc.ReadFile(path)
			if err != nil {
				return err
			}
			poc, err := ParsePocXrayData(content)
			if err != nil {
				return err
			}
			items = append(items, poc)
		}
		return nil
	})

	if err != nil {
		fmt.Println(err)
	}

	return items
}
