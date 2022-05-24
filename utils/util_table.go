package utils

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"os"
)

func ShowTable(title string, header table.Row, data []table.Row) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetTitle(title)
	t.AppendHeader(header)
	t.AppendRows(data)
	t.Render()
}
