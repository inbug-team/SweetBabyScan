package plugin_scan_weak

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/utils"
	"golang.org/x/crypto/ssh"
	"net"
	"time"
)

func CheckSSH(ip, user, pwd string, port uint) bool {
	result := false
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(pwd)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 6 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf(`%s:%d`, ip, port), config)
	if err == nil {
		defer func() {
			err := client.Close()
			utils.PrintErr(err)
		}()
		session, err := client.NewSession()
		if err == nil {
			errEcho := session.Run("echo hello")
			if errEcho == nil {
				defer func() {
					err := session.Close()
					utils.PrintErr(err)
				}()
				result = true
			}
		}

	}
	return result
}
