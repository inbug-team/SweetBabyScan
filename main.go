package main

import (
	_ "embed"
	"fmt"
	"github.com/common-nighthawk/go-figure"
	"github.com/inbug-team/SweetBabyScan/config"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_nuclei"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_poc_xray/load"
	"github.com/inbug-team/SweetBabyScan/core/plugins/plugin_scan_weak"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_host"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_poc_nuclei"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_poc_xray"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_port"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_site"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_vul"
	"github.com/inbug-team/SweetBabyScan/core/tasks/task_scan_weak"
	"github.com/inbug-team/SweetBabyScan/initializes"
	"github.com/inbug-team/SweetBabyScan/models"
	"github.com/inbug-team/SweetBabyScan/utils"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/nasdf/ulimit"
	"github.com/projectdiscovery/goflags"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var isScreen = false

func init() {
	os.Mkdir("./static", 0777)
	isScreen = initializes.InitAll()
}

// 过滤函数
func fnFilterNuclei(pocName, vulLevel string, params models.Params) bool {
	statusFPN, statusFVL := false, false
	// 筛选漏洞名
	for _, s1 := range strings.Split(strings.ToLower(params.FilterPocName), ",") {
		statusFPN = statusFPN || strings.Contains(pocName, s1)
	}
	// 筛选漏洞等级
	if params.FilterVulLevel != "" {
		for _, s4 := range strings.Split(strings.ToLower(params.FilterVulLevel), ",") {
			statusFVL = statusFVL || (s4 == vulLevel)
		}
	} else {
		statusFVL = true
	}
	return statusFPN && statusFVL
}

// 过滤函数
func fnFilterXray(pocName string, params models.Params) bool {
	statusFPN := false
	// 筛选漏洞名
	for _, s1 := range strings.Split(strings.ToLower(params.FilterPocName), ",") {
		statusFPN = statusFPN || strings.Contains(pocName, s1)
	}
	return statusFPN
}

// 查询 poc nuclei
func findPocsNuclei(p models.Params) {
	fmt.Println("Finding......，Please be patient !")
	pocNuclei := plugin_scan_poc_nuclei.ParsePocNucleiFiles(config.DirPocNuclei)
	rows := plugin_scan_poc_nuclei.ParsePocNucleiToTable(pocNuclei)
	rows, total := plugin_scan_poc_nuclei.FilterPocNucleiTable(rows, fnFilterNuclei, p)
	utils.ShowTable(
		fmt.Sprintf("Collection Of Poc Nuclei <%d rows>", total),
		table.Row{"ID", "Poc", "Catalog", "Protocol", "Level"},
		rows,
	)
}

// 查询 poc xray
func findPocsXray(p models.Params) {
	fmt.Println("Finding......，Please be patient !")
	pocXray := load.ParsePocXrayFiles(config.DirPocXray)
	rows := load.ParsePocXrayToTable(pocXray)
	rows, total := load.FilterPocXrayTable(rows, fnFilterXray, p)
	utils.ShowTable(
		fmt.Sprintf("Collection Of Poc Xray <%d rows>", total),
		table.Row{"ID", "Poc", "Description"},
		rows,
	)
}

// 读取文件
func readFileStr(data string) (newData string, status bool) {
	if strings.HasSuffix(strings.ToLower(data), ".txt") {
		dataList, err := utils.ReadLinesFormFile(data)
		if err != nil {
			fmt.Println(fmt.Sprintf("[x]读取%s文件失败，失败原因：%s", data, err.Error()))
			os.Exit(0)
		}
		newData = strings.Trim(strings.Join(dataList, ","), ",")
		status = true
	}
	return
}

func readFileArr(data string) (newData []string, status bool) {
	if strings.HasSuffix(strings.ToLower(data), ".txt") {
		dataList, err := utils.ReadLinesFormFile(data)
		if err != nil {
			fmt.Println(fmt.Sprintf("[x]读取%s文件失败，失败原因：%s", data, err.Error()))
			os.Exit(0)
		}
		newData = dataList
		status = true
	} else {
		fmt.Println("[x]文件必须以,txt结尾")
		os.Exit(0)
	}
	return
}

// 弱口令生成器
func generatePwd(pwdPrefix, pwdCenter, pwdSuffix string) (passwords []string) {
	//fmt.Println("Password Generator 弱口令生成器，多个以空格隔开")
	//reader := bufio.NewReader(os.Stdin)
	//fmt.Print("[password prefix] > ")
	//pwdPrefix, _ = reader.ReadString('\n')
	//fmt.Print("[password center] > ")
	//pwdCenter, _ = reader.ReadString('\n')
	//fmt.Print("[password suffix] > ")
	//pwdSuffix, _ = reader.ReadString('\n')

	_pwdPrefix := strings.Split(strings.TrimSpace(pwdPrefix), ",")
	_pwdCenter := strings.Split(strings.TrimSpace(pwdCenter), ",")
	_pwdSuffix := strings.Split(strings.TrimSpace(pwdSuffix), ",")

	if len(_pwdPrefix) == 0 {
		_pwdPrefix = []string{""}
	}
	if len(_pwdCenter) == 0 {
		_pwdCenter = []string{""}
	}
	if len(_pwdSuffix) == 0 {
		_pwdSuffix = []string{""}
	}

	for _, v1 := range _pwdPrefix {
		for _, v2 := range _pwdCenter {
			for _, v3 := range _pwdSuffix {
				passwords = append(passwords, fmt.Sprintf(`%s%s%s`, v1, v2, v3))
			}
		}
	}
	//fmt.Println(fmt.Sprintf("[password result] %d record:", len(passwords)))
	//fmt.Println(strings.Join(passwords, " "))

	passwords = utils.RemoveRepeatedElement(passwords)
	return
}

// 执行任务
func doTask(p models.Params) {
	fmt.Println("Loading......，Please be patient !")
	now := time.Now()

	// 定义保存文件
	if p.OutputExcel == "" {
		p.OutputExcel = fmt.Sprintf("./result-%s.xlsx", now.Format("20060102150405"))
	} else {
		if !strings.HasSuffix(strings.ToLower(p.OutputExcel), ".xlsx") {
			fmt.Println("[x]保存文件仅支持excel，必须以xlsx结尾")
			os.Exit(0)
		}
	}

	// 加载乱序IP
	if tmpHost, status := readFileStr(p.Host); status {
		p.Host = tmpHost
	}

	if tmpHostBlack, status := readFileStr(p.HostBlack); status {
		p.HostBlack = tmpHostBlack
	}

	p.IPs = utils.GetIps(p.Host, p.HostBlack)

	// 初始化excel
	utils.InitExcel(p.OutputExcel, config.TmpExcel)

	// 加载探针指纹
	p.RuleProbe = config.RuleProbe

	// 加载端口
	portsMap := map[string]string{
		"tiny":     "21,22,53,80,81,135,137,139,161,443,445,1443,1521,1900,3306,3389,5353,5432,6379,8000,8080,8983,8089,9000,9200,11211,27017",
		"web":      "21,22,53,80,81,82,83,84,85,86,87,88,89,90,91,92,98,99,135,137,139,161,443,445,800,801,808,880,888,889,1000,1010,1080,1081,1082,1099,1118,1443,1521,1888,1900,2008,2020,2100,2375,2379,3000,3008,3128,3306,3389,3505,5353,5432,5555,6080,6379,6648,6868,7000,7001,7002,7003,7004,7005,7007,7008,7070,7071,7074,7078,7080,7088,7200,7680,7687,7688,7777,7890,8000,8001,8002,8003,8004,8006,8008,8009,8010,8011,8012,8016,8018,8020,8028,8030,8038,8042,8044,8046,8048,8053,8060,8069,8070,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8091,8092,8093,8094,8095,8096,8097,8098,8099,8100,8101,8108,8118,8161,8172,8180,8181,8200,8222,8244,8258,8280,8288,8300,8360,8443,8448,8484,8800,8834,8838,8848,8858,8868,8879,8880,8881,8888,8899,8983,8989,9000,9001,9002,9008,9010,9043,9060,9080,9081,9082,9083,9084,9085,9086,9087,9088,9089,9090,9091,9092,9093,9094,9095,9096,9097,9098,9099,9100,9200,9443,9448,9800,9981,9986,9988,9998,9999,10000,10001,10002,10004,10008,10010,10250,11211,12018,12443,14000,16080,18000,18001,18002,18004,18008,18080,18082,18088,18090,18098,19001,20000,20720,20880,21000,21501,21502,27017,28018",
		"normal":   "7,11,13,15,17,19,21,22,23,25,26,30,31,32,36,37,38,43,49,51,53,67,69,70,79,80,81,82,83,84,85,86,88,89,98,102,104,110,111,113,119,121,123,135,137,138,139,143,161,162,175,179,199,211,264,280,311,389,391,443,444,445,449,465,500,502,503,505,512,515,520,523,540,548,554,564,587,620,623,626,631,636,646,666,705,771,777,789,800,801,808,853,873,876,880,888,898,900,901,902,990,992,993,994,995,999,1000,1010,1022,1023,1024,1025,1026,1027,1042,1080,1099,1177,1194,1200,1201,1212,1214,1234,1241,1248,1260,1290,1311,1314,1344,1400,1433,1434,1443,1471,1494,1503,1505,1515,1521,1554,1588,1604,1610,1645,1701,1720,1723,1741,1777,1812,1830,1863,1880,1883,1900,1901,1911,1935,1947,1962,1967,1991,1993,2000,2001,2002,2010,2020,2022,2030,2049,2051,2052,2053,2055,2064,2077,2080,2082,2083,2086,2087,2094,2095,2096,2121,2123,2152,2160,2181,2222,2223,2252,2306,2323,2332,2375,2376,2379,2396,2401,2404,2406,2424,2425,2427,2443,2455,2480,2491,2501,2525,2600,2601,2628,2715,2809,2869,3000,3001,3002,3005,3052,3075,3097,3128,3260,3280,3283,3288,3299,3306,3307,3310,3311,3312,3333,3337,3352,3372,3388,3389,3390,3391,3443,3460,3520,3522,3523,3524,3525,3528,3531,3541,3542,3671,3689,3690,3702,3749,3780,3784,3790,4000,4022,4040,4050,4063,4064,4070,4155,4300,4369,4430,4433,4440,4443,4444,4500,4505,4506,4567,4660,4664,4711,4712,4730,4782,4786,4800,4840,4842,4848,4880,4911,4949,5000,5001,5002,5004,5005,5006,5007,5008,5009,5050,5051,5060,5061,5084,5093,5094,5095,5111,5222,5258,5269,5280,5351,5353,5357,5400,5427,5432,5443,5550,5554,5555,5560,5577,5598,5601,5631,5632,5672,5673,5678,5683,5800,5801,5802,5820,5900,5901,5902,5903,5938,5984,5985,5986,6000,6001,6002,6003,6006,6060,6068,6080,6103,6346,6363,6379,6443,6488,6544,6560,6565,6581,6588,6590,6600,6664,6665,6666,6667,6668,6669,6697,6699,6780,6782,6881,6969,6998,7000",
		"database": "1433,1521,1583,2100,2049,3050,3306,3351,5000,5432,5433,5601,5984,6082,6379,7474,8080,8088,8089,8098,8471,9000,9160,9200,9300,9471,11211,15672,19888,27017,27019,27080,28017,50000,50070,50090",
		"caffe":    "21,22,23,25,53,80,110,111,135,137,139,161,389,443,445,515,548,873,902,1080,1433,1900,2181,2375,2379,3128,3306,3389,5060,5222,5351,5353,5555,5672,5683,5900,6379,7001,8080,9000,9100,9200,11211",
		"iot":      "21,22,23,25,80,81,82,83,84,88,137,143,443,445,554,631,1080,1883,1900,2000,2323,4433,4443,4567,5222,5683,7474,7547,8000,8023,8080,8081,8443,8088,8883,8888,9000,9090,9999,10000,37777,49152",
		"all":      "1-65535",
	}
	if value, ok := portsMap[p.Port]; ok {
		p.Ports = utils.ParsePort(value)
	} else {
		p.Ports = utils.ParsePort(p.Port)
	}

	// 加载协议
	switch p.Protocol {
	case "tcp":
		p.Protocols = []string{"tcp"}
	case "udp":
		p.Protocols = []string{"udp"}
	case "tcp+udp":
		p.Protocols = []string{"tcp", "udp"}
	}

	// 1.主机存活检测
	if !p.NoScanHost {
		p.IPs = task_scan_host.DoTaskScanHost(p)
	}

	// 2.端口服务扫描
	p.Urls, p.WaitVul, p.WaitWeak = task_scan_port.DoTaskScanPort(p)

	// 3.网站内容爬虫
	p.Sites = task_scan_site.DoTaskScanSite(p)

	// 4.POC Nuclei+Xray漏洞探测
	if !p.NoScanPoc {
		// 加载POC等级
		if p.FilterVulLevel == "" {
			p.FilterVulLevel = "critical,high,medium"
		} else if p.FilterVulLevel == "all" {
			p.FilterVulLevel = "critical,high,medium,low,info,unknown"
		}

		// 加载筛选POC Nuclei
		pocNuclei := plugin_scan_poc_nuclei.ParsePocNucleiFiles(config.DirPocNuclei)
		p.PocNuclei, _ = plugin_scan_poc_nuclei.FilterPocNucleiData(pocNuclei, fnFilterNuclei, p)

		// 加载筛选POC Xray
		pocXray := load.ParsePocXrayFiles(config.DirPocXray)
		p.PocXray, _ = load.FilterPocXrayData(pocXray, fnFilterXray, p)

		index := task_scan_poc_nuclei.DoTaskScanPocNuclei(p)
		task_scan_poc_xray.DoTaskScanPocXray(p, index)
	}

	// 6.高危系统漏洞探测
	if !p.NoScanVul {
		task_scan_vul.DoTaskScanVul(p)
	}

	// 7.弱口令爆破
	if !p.NoScanWeak {
		// 组装爆破并发
		p.WorkerScanWeakMap = map[string]int{}
		items := strings.Split(p.WorkerScanWeak, ",")
		for _, v := range items {
			val := strings.Split(v, ":")
			value, _ := strconv.Atoi(val[1])
			p.WorkerScanWeakMap[val[0]] = value
		}

		// 加载弱口令字典
		p.UserPass = plugin_scan_weak.ParseUserPass(config.Passwords)

		// 指定协议
		if p.ServiceScanWeak != "" {
			services := strings.Split(p.ServiceScanWeak, ",")
			for service := range p.UserPass {
				if utils.Contains(services, service) < 0 {
					delete(p.UserPass, service)
				}
			}
		}

		// 覆盖模式
		if p.WUser != "" && p.WPass != "" {
			if tmpUser, status := readFileArr(p.WUser); status {
				for key := range p.UserPass {
					p.UserPass[key]["user"] = utils.RemoveRepeatedElement(tmpUser)
				}
			}
			if tmpPass, status := readFileArr(p.WPass); status {
				for key := range p.UserPass {
					p.UserPass[key]["pass"] = utils.RemoveRepeatedElement(tmpPass)
				}
			}
		}

		// 追加模式
		if p.AUser != "" && p.APass != "" {
			if tmpUser, status := readFileArr(p.AUser); status {
				for key := range p.UserPass {
					p.UserPass[key]["user"] = utils.RemoveRepeatedElement(append(p.UserPass[key]["user"], tmpUser...))
				}
			}
			if tmpPass, status := readFileArr(p.APass); status {
				for key := range p.UserPass {
					p.UserPass[key]["pass"] = utils.RemoveRepeatedElement(append(p.UserPass[key]["pass"], tmpPass...))
				}
			}
		}

		// 获取输入弱口令
		var gPwd []string
		if p.IsAPass || p.IsWPass {
			gPwd = generatePwd(p.PasswordPrefix, p.PasswordCenter, p.PasswordSuffix)
		}

		// 追加弱口令生成器
		if p.IsAPass {
			for key := range p.UserPass {
				p.UserPass[key]["pass"] = utils.RemoveRepeatedElement(append(p.UserPass[key]["pass"], gPwd...))
			}
		}

		// 覆盖弱口令生成器
		if p.IsWPass {
			for key := range p.UserPass {
				p.UserPass[key]["pass"] = gPwd
			}
		}

		task_scan_weak.DoTaskScanWeak(p)
	}

	fmt.Println(fmt.Sprintf("Output Excel File：%s", p.OutputExcel))
}

func main() {
	err := ulimit.SetRlimit(65535)
	if err != nil {
		fmt.Println(err)
	}
	myFigure := figure.NewColorFigure("SBScan", "doom", "red", true)
	myFigure.Print()
	fmt.Println("全称：SweetBabyScan，甜心宝贝扫描器")
	fmt.Println("Version <0.0.6> Made By InBug")

	soft, hard, err := ulimit.GetRlimit()
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(fmt.Sprintf("ulimit soft: %d ｜ulimit hard: %d", soft, hard))
	if isScreen {
		fmt.Println("chrome headless ready")
	} else {
		fmt.Println("chrome headless not ready")
	}

	p := models.Params{}

	flagSet := goflags.NewFlagSet()

	flagSet.BoolVarP(&p.IsLog, "isLog", "il", true, "是否显示日志")
	flagSet.BoolVarP(&p.IsScreen, "isScreen", "is", isScreen, "是否启用截图")
	flagSet.StringVarP(&p.OutputExcel, "outputExcel", "oe", "", "指定保存excel文件路径[以.xlsx结尾]")
	flagSet.StringVarP(&p.Host, "host", "h", "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8", "检测网段或者txt文件[以.txt结尾，一行一组回车换行]")
	flagSet.StringVarP(&p.Port, "port", "p", "web", "端口范围：tiny[精简]、web[WEB服务]、normal[常用]、database[数据库]、caffe[咖啡厅/酒店/机场]、iot[物联网]、all[全部]、自定义")
	flagSet.StringVarP(&p.Protocol, "protocol", "pt", "tcp+udp", "端口范围：tcp、udp、tcp+udp")
	flagSet.StringVarP(&p.HostBlack, "hostBlack", "hb", "", "排除网段")
	flagSet.StringVarP(&p.MethodScanHost, "methodScanHost", "msh", "PING", "验存方式：PING、ICMP")
	flagSet.IntVarP(&p.WorkerScanHost, "workerScanHost", "wsh", 250, "存活并发")
	flagSet.IntVarP(&p.TimeOutScanHost, "timeOutScanHost", "tsh", 3, "存活超时")
	flagSet.IntVarP(&p.Rarity, "rarity", "r", 10, "优先级")
	flagSet.IntVarP(&p.WorkerScanPort, "workerScanPort", "wsp", 250, "扫描并发")
	flagSet.IntVarP(&p.TimeOutScanPortConnect, "timeOutScanPortConnect", "tspc", 3, "端口扫描连接超时")
	flagSet.IntVarP(&p.TimeOutScanPortSend, "timeOutScanPortSend", "tsps", 3, "端口扫描发包超时")
	flagSet.IntVarP(&p.TimeOutScanPortRead, "timeOutScanPortRead", "tspr", 3, "端口扫描读取超时")
	flagSet.BoolVarP(&p.IsNULLProbeOnly, "isNULLProbeOnly", "inpo", false, "使用空探针")
	flagSet.BoolVarP(&p.IsUseAllProbes, "isUseAllProbes", "iuap", false, "使用全量探针")
	flagSet.IntVarP(&p.WorkerScanSite, "workerScanSite", "wss", runtime.NumCPU()*2, "爬虫并发")
	flagSet.IntVarP(&p.TimeOutScanSite, "timeOutScanSite", "tss", 3, "爬虫超时")
	flagSet.IntVarP(&p.TimeOutScreen, "timeOutScreen", "ts", 60, "截图超时")
	flagSet.BoolVarP(&p.ListPocNuclei, "listPocNuclei", "lpn", false, "是否列举Poc Nuclei")
	flagSet.BoolVarP(&p.ListPocXray, "ListPocXray", "lpx", false, "是否列举Poc Xray")
	flagSet.StringVarP(&p.FilterPocName, "filterPocName", "fpn", "", "筛选POC名称，多个关键字英文逗号隔开")
	flagSet.StringVarP(&p.FilterVulLevel, "filterVulLevel", "fvl", "", "筛选POC严重等级：critical[严重] > high[高危] > medium[中危] > low[低危] > info[信息]、unknown[未知]、all[全部]，多个关键字英文逗号隔开")
	flagSet.IntVarP(&p.TimeOutScanPocNuclei, "timeOutScanPocNuclei", "tspn", 6, "PocNuclei扫描超时")
	flagSet.IntVarP(&p.WorkerScanPoc, "workerScanPoc", "wsPoc", 100, "Poc并发")
	flagSet.IntVarP(&p.GroupScanWeak, "groupScanWeak", "gsw", 20, "爆破分组")
	flagSet.StringVarP(&p.WorkerScanWeak, "workerScanWeak", "wsw", "ssh:1,smb:1,snmp:1,sqlserver:4,mysql:4,mongodb:4,postgres:4,redis:6,ftp:1,clickhouse:4,elasticsearch:4", "爆破并发，键值对形式，英文逗号分隔")
	flagSet.IntVarP(&p.TimeOutScanWeak, "timeOutScanWeak", "tsw", 6, "爆破超时")
	flagSet.BoolVarP(&p.NoScanHost, "noScanHost", "nsh", false, "跳过主机存活检测")
	flagSet.BoolVarP(&p.NoScanWeak, "noScanWeak", "nsw", false, "跳过弱口令爆破")
	flagSet.BoolVarP(&p.NoScanPoc, "noScanPoc", "nsp", false, "跳过POC漏洞验证")
	flagSet.BoolVarP(&p.NoScanVul, "noScanVul", "nsv", false, "跳过高危系统漏洞探测")
	flagSet.StringVarP(&p.ServiceScanWeak, "serviceScanWeak", "ssw", "", fmt.Sprintf("指定爆破协议：%s，多个协议英文逗号分隔，默认全部", config.Service))
	flagSet.StringVarP(&p.AUser, "aUser", "au", "", "追加弱口令账号字典[以.txt结尾]")
	flagSet.StringVarP(&p.APass, "aPass", "ap", "", "追加弱口令密码字典[以.txt结尾]")
	flagSet.StringVarP(&p.WUser, "wUser", "wu", "", "覆盖弱口令账号字典[以.txt结尾]")
	flagSet.StringVarP(&p.WPass, "wPass", "wp", "", "覆盖弱口令密码字典[以.txt结尾]")
	flagSet.BoolVarP(&p.IsAPass, "isAPass", "iap", false, "是否追加弱口令生成器")
	flagSet.BoolVarP(&p.IsWPass, "isWPass", "iwp", false, "是否覆盖弱口令生成器")
	flagSet.StringVarP(&p.PasswordPrefix, "passwordPrefix", "pp", "", "密码前缀，多个英文逗号分隔")
	flagSet.StringVarP(&p.PasswordCenter, "passwordCenter", "pc", "", "密码中位，多个英文逗号分隔")
	flagSet.StringVarP(&p.PasswordSuffix, "passwordSuffix", "ps", "", "密码后缀，多个英文逗号分隔")
	flagSet.Parse()

	plugin_scan_poc_nuclei.InitPocNucleiExecOpts(p.TimeOutScanPocNuclei)

	if p.ListPocNuclei {
		findPocsNuclei(p)
	} else if p.ListPocXray {
		findPocsXray(p)
	} else {
		doTask(p)
	}

}
