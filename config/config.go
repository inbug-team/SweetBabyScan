package config

import (
	"embed"
	"encoding/json"
	"github.com/inbug-team/SweetBabyScan/models"
	"math/rand"
	"time"
)

//go:embed probe/service.txt
var RuleProbe string

//go:embed probe/apps.json
var AppStr string

//go:embed probe/ua.json
var UAStr string

//go:embed probe/pocs/nuclei
var DirPocNuclei embed.FS

//go:embed probe/pocs/xray/pocs
var DirPocXray embed.FS

//go:embed probe/tmp.xlsx
var TmpExcel []byte

//go:embed probe/passwords
var Passwords embed.FS

// cms 指纹
var AppsData models.OutputFingerprints

// ua
var UA []string

// 弱口令爆破并发
var WorkerMap = map[string]int{
	"ssh":           1,
	"smb":           1,
	"snmp":          1,
	"sqlserver":     4,
	"mysql":         4,
	"mongodb":       4,
	"postgres":      4,
	"redis":         6,
	"ftp":           1,
	"clickhouse":    4,
	"elasticsearch": 4,
}

// 弱口令协议
var Service = "ssh,smb,snmp,sqlserver,mysql,mongodb,postgres,redis,ftp,clickhouse,elasticsearch"

func init() {
	err := json.Unmarshal([]byte(UAStr), &UA)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal([]byte(AppStr), &AppsData)
	if err != nil {
		panic(err)
	}
}

func GetUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	ua := UA
	i := rand.Intn(len(ua))
	return ua[i]
}
