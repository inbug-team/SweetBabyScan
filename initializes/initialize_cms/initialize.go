package initialize_cms

import (
	cms "github.com/projectdiscovery/wappalyzergo"
)

var CMSClient *cms.Wappalyze

func InitCMS() {
	CMSClient, _ = cms.New()
}
