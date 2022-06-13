package plugin_scan_host

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// PING检测存活
func ScanHostByPing(host string) bool {
	var command *exec.Cmd
	env := "bash"
	command = exec.Command(env, "-c", fmt.Sprintf("ping -c 1 -w 1 %s >/dev/null && echo true || echo false", host))
	outInfo := bytes.Buffer{}
	if command == nil {
		return false
	}
	command.Stdout = &outInfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outInfo.String(), "true") {
			return true
		} else {
			return false
		}
	}
}
