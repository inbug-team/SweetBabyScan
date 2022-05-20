package initializes

import (
	"SweetBabyScan/initializes/initialize_http_client"
	"SweetBabyScan/initializes/initialize_screenshot"
)

func InitAll() {
	initialize_screenshot.InitScreenShot()
	initialize_http_client.InitHttpClient()
}
