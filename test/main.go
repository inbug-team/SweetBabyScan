package main

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_host"
)

func main() {
	status := plugin_scan_host.ScanHostByPing("www.goolasasas.com")
	fmt.Println(status)
}
