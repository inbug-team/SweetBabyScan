package plugin_scan_cms1

import (
	"github.com/inbug-team/SweetBabyScan/initializes/initialize_cms"
	"net/http"
)

func ScanCms1(header http.Header, data []byte) map[string]struct{} {
	fingerPrints := initialize_cms.CMSClient.Fingerprint(header, data)
	return fingerPrints
}
