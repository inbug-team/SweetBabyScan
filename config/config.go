package config

import (
	"SweetBabyScan/models"
	_ "embed"
	"encoding/json"
	"math/rand"
	"time"
)

//go:embed probe/service.txt
var RuleProbe string

//go:embed probe/apps.json
var AppStr string

//go:embed probe/ua.json
var UAStr string

// cms指纹
var AppsData models.OutputFingerprints

// ua
var UA []string

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
