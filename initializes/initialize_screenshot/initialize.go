package initialize_screenshot

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_host"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_site"
	"github.com/inbug-team/SweetBabyScan/utils"
	"time"
)

func InitScreenShot() bool {
	path := "./static/ip.png"
	status, _ := utils.PathExists(path)
	if status {
		return status
	}

	domain := "myip.ipip.net"
	status = plugin_scan_host.ScanHostByPing(domain)
	if status {
		fmt.Println("downloading chrome headless......")
		plugin_scan_site.DoFullScreenshot(fmt.Sprintf("http://%s/", domain), path, 120*time.Second)
	}
	return status
}
