package plugin_scan_weak

import (
	"fmt"
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
			client.Close()
		}()
		session, err := client.NewSession()
		if err == nil {
			defer func() {
				session.Close()
			}()
			result = true
		}

	}
	return result
}
