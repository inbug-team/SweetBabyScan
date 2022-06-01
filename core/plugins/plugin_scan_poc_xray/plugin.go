package plugin_scan_poc_xray

import (
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_xray/lib"
	"github.com/inbug-team/SweetBabyScan/models"
	"net/http"
)

func ScanPocXray(oReq *http.Request, p *models.DataPocXray) (bool, error, string) {
	return lib.ExecutePoc(oReq, p)
}
