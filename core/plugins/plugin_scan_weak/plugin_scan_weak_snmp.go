package plugin_scan_weak

import (
	"github.com/gosnmp/gosnmp"
	"time"
)

func CheckSNMP(ip, pwd string, port uint) bool {
	flag := false

	gosnmp.Default.Target = ip
	gosnmp.Default.Port = uint16(port)
	gosnmp.Default.Community = pwd
	gosnmp.Default.Timeout = 4 * time.Second

	err := gosnmp.Default.Connect()
	if err == nil {
		oidList := []string{"1.3.6.1.2.1.1.4.0", "1.3.6.1.2.1.1.7.0"}
		_, err := gosnmp.Default.Get(oidList)
		if err == nil {
			flag = true
		}
	}

	return flag
}
