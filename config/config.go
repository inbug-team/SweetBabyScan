package config

import (
	"embed"
	"encoding/json"
	"math/rand"
	"time"
)

//go:embed probe/service.txt
var RuleProbe string

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

// ua
var UA []string

// 弱口令协议
var Service = "ssh,smb,rdp,snmp,sqlserver,mysql,mongodb,postgres,redis,ftp,clickhouse,elasticsearch,oracle,memcached"

func init() {
	err := json.Unmarshal([]byte(UAStr), &UA)
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
