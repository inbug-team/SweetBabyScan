package initializes

import (
	"github.com/inbug-team/SweetBabyScan/initializes/initialize_cms"
	"github.com/inbug-team/SweetBabyScan/initializes/initialize_http_client"
)

func InitAll() {
	initialize_http_client.InitHttpClient()
	initialize_cms.InitCMS()
}
