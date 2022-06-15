package initialize_screenshot

import (
	"context"
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_host"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_site"
	"github.com/inbug-team/SweetBabyScan/utils"
	"time"
)

func Download(ctx context.Context, domain, path string) bool {
	ch := make(chan bool, 1)
	go func() {
		fmt.Println("downloading chrome headless......")
		plugin_scan_site.DoFullScreenshot(fmt.Sprintf("http://%s/", domain), path, 60*time.Second)
		ch <- true
	}()
	select {
	case <-ch:
		fmt.Println("download finish !")
		return true
	case <-ctx.Done():
		fmt.Println("download timeout !")
		return false
	}
}

func InitScreenShot() bool {
	path := "./static/ip.png"
	status, _ := utils.PathExists(path)
	if status {
		return status
	}

	domain := "myip.ipip.net"
	status = plugin_scan_host.ScanHostByPing(domain)
	if status {
		ctx, cancel := context.WithTimeout(context.Background(), 65*time.Second)
		status = Download(ctx, domain, path)
		cancel()
	}
	return status
}
