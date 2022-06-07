package plugin_scan_host

// PING检测存活
func ScanHostByPing(host string) bool {
	var command *exec.Cmd
	command = exec.Command("cmd", "/c", fmt.Sprintf("ping -n 1 -w 1 %s && echo true || echo false", host))
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

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
