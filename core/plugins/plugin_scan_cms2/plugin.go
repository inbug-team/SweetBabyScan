package plugin_scan_cms2

import (
	"SweetBabyScan/core/plugins/plugin_scan_cms2/info"
	"crypto/md5"
	"fmt"
	"regexp"
)

type CheckData struct {
	Body    []byte
	Headers string
}

type CmsResult struct {
	CmsName    string
	CmsType    string
	CmsRule    string
	CmsMd5Str  string
	CmsMd5Name string
}

func InfoCheck(url string, data CheckData) (result CmsResult) {
	var matched bool

	for _, rule := range info.RuleDataList {
		if rule.Type == "code" {
			matched, _ = regexp.MatchString(rule.Rule, string(data.Body))
		} else {
			matched, _ = regexp.MatchString(rule.Rule, data.Headers)
		}
		if matched == true {
			result.CmsName = rule.Name
			result.CmsType = rule.Type
			result.CmsRule = rule.Rule
			break
		}
	}
	flag, name, md5Str := CalcMd5(data.Body)

	if flag == true {
		result.CmsMd5Str = md5Str
		result.CmsMd5Name = name
	}

	//if result.CmsName != "" {
	//	fmt.Println(fmt.Sprintf("[+]发现web系统：%-25v %s ", url, result.CmsName))
	//}
	return result
}

func CalcMd5(Body []byte) (bool, string, string) {
	has := md5.Sum(Body)
	md5str := fmt.Sprintf("%x", has)
	for _, md5data := range info.Md5DataList {
		if md5str == md5data.Md5Str {
			return true, md5data.Name, md5data.Md5Str
		}
	}
	return false, "", ""
}
