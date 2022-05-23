package plugin_scan_weak

import (
	"github.com/stacktitan/smb/smb"
)

func CheckSMB(ip, user, pwd string, port uint) bool {
	flag := false
	options := smb.Options{
		Host:        ip,
		Port:        int(port),
		User:        user,
		Password:    pwd,
		Domain:      "",
		Workstation: "",
	}

	session, err := smb.NewSession(options, false)
	if err == nil {
		if session.IsAuthenticated {
			flag = true
		}
		session.Close()
	}
	return flag
}
