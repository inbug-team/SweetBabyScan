package initialize_screenshot

import (
	"SweetBabyScan/core/plugins/plugin_scan_site"
	"SweetBabyScan/utils"
	"fmt"
	"time"
)

func InitScreenShot() {
	path := "./static/ip.png"
	if status, _ := utils.PathExists(path); !status {
		fmt.Println("downloading chrome headless......")
		plugin_scan_site.DoFullScreenshot("http://myip.ipip.net/", path, 120*time.Second)
	}
}
