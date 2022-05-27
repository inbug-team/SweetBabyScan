package plugin_scan_weak

import (
	"fmt"
	"github.com/jlaffaye/ftp"
	"time"
)

func CheckFTP(ip, user, pwd string, port uint) bool {
	client, err := ftp.Dial(fmt.Sprintf(`%s:%d`, ip, port), ftp.DialWithTimeout(6*time.Second))

	if err != nil {
		return false
	}

	err = client.Login(user, pwd)
	if err != nil {
		return false
	}

	client.Quit()

	return true
}
