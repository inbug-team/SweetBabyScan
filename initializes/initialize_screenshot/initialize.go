package initialize_screenshot

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_site"
	"github.com/inbug-team/SweetBabyScan/utils"
	"time"
)

func InitScreenShot() {
	path := "./static/ip.png"
	if status, _ := utils.PathExists(path); !status {
		fmt.Println("downloading chrome headless......")
		plugin_scan_site.DoFullScreenshot("http://myip.ipip.net/", path, 120*time.Second)
	}
}
