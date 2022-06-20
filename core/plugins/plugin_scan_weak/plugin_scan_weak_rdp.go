package plugin_scan_weak

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/core/grdp"
	"github.com/inbug-team/SweetBabyScan/core/grdp/glog"
)

func CheckRDP(ip, user, pwd string, port uint) bool {
	var err error
	g := grdp.NewClient(fmt.Sprintf("%s:%d", ip, port), glog.NONE)
	// SSL协议登录测试
	err = g.LoginForSSL("", user, pwd)
	if err == nil {
		return true
	}
	if err.Error() != "PROTOCOL_RDP" {
		return false
	}
	// RDP协议登录测试
	err = g.LoginForRDP("", user, pwd)
	if err == nil {
		return true
	} else {
		return false
	}
}
