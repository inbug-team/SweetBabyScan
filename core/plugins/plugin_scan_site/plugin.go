package plugin_scan_site

import (
	"encoding/json"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/inbug-team/SweetBabyScan/config"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_cms1"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_cms2"
	"github.com/inbug-team/SweetBabyScan/initializes/initialize_http_client"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"math/big"
	"net/http"
	netUrl "net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Org struct {
	Country            string `json:"country"`             // 国家或地区
	Province           string `json:"province"`            // 省/市/自治区
	Locality           string `json:"locality"`            // 所在地
	OrganizationalUnit string `json:"organizational_unit"` // 组织单位
	Organization       string `json:"organization"`        // 组织
	CommonName         string `json:"common_name"`         // 常用名称
	StreetAddress      string `json:"street_address"`      // 街道地址
	PostalCode         string `json:"postal_code"`         // 邮政编码
}

type TLS struct {
	Proto                 string      `json:"proto"`                   // 协议
	Subject               Org         `json:"subject"`                 // 主题名称
	Issuer                Org         `json:"issuer"`                  // 签发者名称
	DNSNames              []string    `json:"dns_names"`               // DNS服务器名称
	CRLDistributionPoints string      `json:"crl_distribution_points"` // CRL分发点 URI
	OCSPServer            string      `json:"ocsp_server"`             // 在线证书状态协议 URI
	IssuingCertificateURL string      `json:"issuing_certificate_url"` // CA签发者 URI
	SubjectKeyId          []uint8     `json:"subject_key_id"`          // 主题密钥标志符
	AuthorityKeyId        []uint8     `json:"authority_key_id"`        // 授权密钥标志符
	SignatureAlgorithm    string      `json:"signature_algorithm"`     // 签名算法
	PublicKeyAlgorithm    string      `json:"public_key_algorithm"`    // 公钥算法
	Signature             []uint8     `json:"signature"`               // 签名
	PublicKey             interface{} `json:"public_key"`              // 公共密钥
	NotBefore             time.Time   `json:"not_before"`              // 有效期开始
	NotAfter              time.Time   `json:"not_after"`               // 有效期结束
	SerialNumber          *big.Int    `json:"serial_number"`           // 序列号
	Version               int         `json:"version"`                 // 版本
}

/*生成UUID*/
func GenerateUUID() string {
	return uuid.NewV4().String()
}

/*执行截图*/
func DoFullScreenshot(url, path string, timeout time.Duration) bool {
	err := rod.Try(func() {
		browser := rod.New().Timeout(timeout).MustConnect()
		defer browser.MustClose()
		page := browser.MustPage(url)
		page.MustWaitLoad().MustScreenshot(path)
	})

	if err != nil {
		//fmt.Println(err)
		return false
	}

	if status, _ := utils.PathExists(path); status {
		return true
	}

	return false
}

func (a TLS) IsEmpty() bool {
	return reflect.DeepEqual(a, TLS{})
}

func GetUrl(link string) string {
	_url, err := netUrl.Parse(link)
	if err != nil {
		return ""
	}
	if _url == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", _url.Scheme, _url.Host)
}

// 转化字符集
func ConvertCharset(dataByte []byte) string {
	sourceCode := string(dataByte)
	if !utf8.Valid(dataByte) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(dataByte)
		sourceCode = string(data)
	}
	return sourceCode
}

func DoRequest(url string) (*http.Request, error) {
	// 构造GET请求
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//fmt.Println("请求错误：", err)
		return nil, err
	}
	request.Header.Set("User-Agent", config.GetUserAgent())
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")
	request.Header.Set("Cookie", "rememberMe=1")
	request.Header.Set("Connection", "close")
	return request, nil
}

func DoScanSite(url string, timeOutScanSite, timeOutScreen int, isScreen bool) (site models.ScanSite) {

	// 构造GET请求
	request, err := DoRequest(url)
	if err != nil {
		return site
	}
	client := initialize_http_client.HttpClientRedirect
	client.Timeout = time.Duration(timeOutScanSite) * time.Second
	resp, err := client.Do(request)

	if err != nil {
	}

	if resp == nil {
		return site
	}

	defer func() {
		resp.Body.Close()
	}()

	if resp.TLS == nil {
		site.Tls = ""
	} else {
		if len(resp.TLS.PeerCertificates) == 0 {
			site.Tls = ""
		} else {
			certInfo := resp.TLS.PeerCertificates[0]
			if certInfo == nil {
				site.Tls = ""
			} else {
				_tls := TLS{
					Proto: resp.Proto,
					Subject: Org{
						Country:            strings.Join(certInfo.Subject.Country, ","),
						Province:           strings.Join(certInfo.Subject.Province, ","),
						Locality:           strings.Join(certInfo.Subject.Locality, ","),
						OrganizationalUnit: strings.Join(certInfo.Subject.OrganizationalUnit, ","),
						Organization:       strings.Join(certInfo.Subject.Organization, ","),
						CommonName:         certInfo.Subject.CommonName,
						StreetAddress:      strings.Join(certInfo.Subject.StreetAddress, ","),
						PostalCode:         strings.Join(certInfo.Subject.PostalCode, ","),
					},
					Issuer: Org{
						Country:            strings.Join(certInfo.Issuer.Country, ","),
						Province:           strings.Join(certInfo.Issuer.Province, ","),
						Locality:           strings.Join(certInfo.Issuer.Locality, ","),
						OrganizationalUnit: strings.Join(certInfo.Issuer.OrganizationalUnit, ","),
						Organization:       strings.Join(certInfo.Issuer.Organization, ","),
						CommonName:         certInfo.Issuer.CommonName,
						StreetAddress:      strings.Join(certInfo.Issuer.StreetAddress, ","),
						PostalCode:         strings.Join(certInfo.Issuer.PostalCode, ","),
					},
					DNSNames:              certInfo.DNSNames,
					CRLDistributionPoints: strings.Join(certInfo.CRLDistributionPoints, ","),
					OCSPServer:            strings.Join(certInfo.OCSPServer, ","),
					IssuingCertificateURL: strings.Join(certInfo.IssuingCertificateURL, ","),
					SubjectKeyId:          certInfo.SubjectKeyId,
					AuthorityKeyId:        certInfo.AuthorityKeyId,
					SignatureAlgorithm:    certInfo.SignatureAlgorithm.String(),
					PublicKeyAlgorithm:    certInfo.PublicKeyAlgorithm.String(),
					Signature:             certInfo.Signature,
					PublicKey:             certInfo.PublicKey,
					NotBefore:             certInfo.NotBefore,
					NotAfter:              certInfo.NotAfter,
					SerialNumber:          certInfo.SerialNumber,
					Version:               certInfo.Version,
				}
				tlsStr, err := json.Marshal(_tls)
				if err == nil {
					site.Tls = string(tlsStr)
				} else {
					site.Tls = ""
				}
			}
		}
	}

	var data []byte
	var respHeader http.Header

	// 获取跳转后的链接
	LinkRedirect := ""
	urlRedirect, _ := resp.Location()
	if urlRedirect != nil {
		LinkRedirect = urlRedirect.String()
	}

	// 判断状态码
	statusCode := resp.StatusCode
	if statusCode >= 300 && statusCode < 400 {
		clientRedirect := initialize_http_client.HttpClient
		clientRedirect.Timeout = time.Duration(timeOutScanSite) * time.Second
		requestRedirect, err := DoRequest(LinkRedirect)
		if err != nil {
			return site
		}

		respRedirect, err := clientRedirect.Do(requestRedirect)
		if err != nil {
			return site
		}

		if respRedirect == nil {
			return site
		}

		defer func() {
			respRedirect.Body.Close()
		}()

		respHeader = respRedirect.Header
		data, err = ioutil.ReadAll(respRedirect.Body)
		if err != nil {
			fmt.Println(url, err)
			return site
		}
	} else {
		respHeader = resp.Header
		data, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Println(url, err)
			return site
		}
	}

	htmlData := strings.NewReader(ConvertCharset(data))

	doc, err := goquery.NewDocumentFromReader(htmlData)
	if err != nil {
		return site
	}

	doc.Find("title").Each(func(i int, s *goquery.Selection) {
		if s != nil {
			site.Title = strings.TrimSpace(strings.Trim(s.Text(), "\n"))
		}
	})

	doc.Find("meta").Each(func(i int, s *goquery.Selection) {
		if s != nil {
			v, ok := "", false
			if v, ok = s.Attr("name"); ok {
				val, _ := s.Attr("content")
				switch strings.ToLower(v) {
				case "keywords":
					site.Keywords = val
				case "description":
					site.Description = val
				}
			}
		}
	})

	header, _ := json.Marshal(respHeader)
	site.Header = string(header)

	host, _ := netUrl.Parse(url)
	site.Port = host.Port()
	site.Ip = strings.Split(host.Host, ":")[0]
	site.StatusCode = strconv.Itoa(statusCode)
	site.Link = url
	site.LinkRedirect = LinkRedirect

	if isScreen {
		_url := strings.ReplaceAll(url, ":", "_")
		_url = strings.ReplaceAll(_url, "/", "_")
		siteImageName := fmt.Sprintf(`%s.png`, _url)

		urlScreen := url
		if site.LinkRedirect != "" {
			urlScreen = site.LinkRedirect
		}

		status := DoFullScreenshot(urlScreen, fmt.Sprintf("./static/%s", siteImageName), time.Duration(timeOutScreen)*time.Second)
		if status {
			site.Image = "/static/" + siteImageName
		}
	}

	// 获取指纹
	cmsResult := plugin_scan_cms2.InfoCheck(plugin_scan_cms2.CheckData{
		Body:    data,
		Headers: string(header),
	})
	site.CmsName = cmsResult.CmsName
	site.CmsMd5Name = cmsResult.CmsMd5Name
	site.CmsMd5Str = cmsResult.CmsMd5Str
	site.CmsType = cmsResult.CmsType
	site.CmsRule = cmsResult.CmsRule

	// 获取cms信息
	cmsClient, err := plugin_scan_cms1.New()
	if err != nil || cmsClient == nil {
		return
	}
	fingerprints := cmsClient.Fingerprint(respHeader, data)
	cmsInfoByte, _ := json.Marshal(fingerprints)
	site.CmsInfo = string(cmsInfoByte)

	return site
}
