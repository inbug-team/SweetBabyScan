package plugin_scan_weak

import (
	"embed"
	"fmt"
	"strings"
)

func ParseUserPass(userPassDir embed.FS) map[string]map[string][]string {
	userPassMap := map[string]map[string][]string{
		"clickhouse":    {"user": []string{}, "pass": []string{}},
		"elasticsearch": {"user": []string{}, "pass": []string{}},
		"ftp":           {"user": []string{}, "pass": []string{}},
		"memcached":     {"user": []string{}, "pass": []string{}},
		"mongodb":       {"user": []string{}, "pass": []string{}},
		"mysql":         {"user": []string{}, "pass": []string{}},
		"oracle":        {"user": []string{}, "pass": []string{}},
		"postgres":      {"user": []string{}, "pass": []string{}},
		"redis":         {"user": []string{}, "pass": []string{}},
		"smb":           {"user": []string{}, "pass": []string{}},
		"rdp":           {"user": []string{}, "pass": []string{}},
		"snmp":          {"user": []string{}, "pass": []string{}},
		"sqlserver":     {"user": []string{}, "pass": []string{}},
		"ssh":           {"user": []string{}, "pass": []string{}},
	}

	rootPath := "probe/passwords/"
	for k, _ := range userPassMap {
		userByte, _ := userPassDir.ReadFile(fmt.Sprintf(`%s%s/user.txt`, rootPath, k))
		passByte, _ := userPassDir.ReadFile(fmt.Sprintf(`%s%s/pass.txt`, rootPath, k))
		userPassMap[k]["user"] = strings.Split(string(userByte), "\n")
		userPassMap[k]["pass"] = strings.Split(string(passByte), "\n")
	}

	return userPassMap
}
