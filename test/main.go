package main

import (
	"SweetBabyScan/initializes/initialize_http_client"
	"fmt"
)

func init() {
	initialize_http_client.InitHttpClient()
}

func main() {
	//data := plugin_scan_site.DoScanSite("https://www.baidu.com", "192.168.188.1", 80)
	//fmt.Println(data)
	fmt.Println((1 - float32(10)/100) * 288)
}
