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

// 执行任务
func doTask(p models.Params) {
	fmt.Println("Loading......，Please be patient !")
	now := time.Now()

	// 定义保存文件
	if p.SaveFile == "" {
		p.SaveFile = fmt.Sprintf("./result-%s.xlsx", now.Format("20060102150405"))
	} else {
		if !strings.HasSuffix(strings.ToLower(p.SaveFile), ".xlsx") {
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
	utils.InitExcel(p.SaveFile, config.TmpExcel)

	// 加载探针指纹
	p.RuleProbe = config.RuleProbe

	// 加载端口
	portsMap := map[string]string{
		"tiny":     "21,22,53,80,135,137,139,161,443,445,1443,1900,3306,3389,5353,5432,6379,8080,8983,9000,27017",
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
			p.FilterVulLevel = "critical,high"
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
					p.UserPass[key]["user"] = tmpUser
				}
			}
			if tmpPass, status := readFileArr(p.WPass); status {
				for key := range p.UserPass {
					p.UserPass[key]["pass"] = tmpPass
				}
			}
		}

		// 追加模式
		if p.AUser != "" && p.APass != "" {
			if tmpUser, status := readFileArr(p.AUser); status {
				for key := range p.UserPass {
					p.UserPass[key]["user"] = append(p.UserPass[key]["user"], tmpUser...)
				}
			}
			if tmpPass, status := readFileArr(p.APass); status {
				for key := range p.UserPass {
					p.UserPass[key]["pass"] = append(p.UserPass[key]["pass"], tmpPass...)
				}
			}
		}

		task_scan_weak.DoTaskScanWeak(p)
	}

	fmt.Println(fmt.Sprintf("Save File：%s", p.SaveFile))
}

func main() {
	err := ulimit.SetRlimit(65535)
	if err != nil {
		fmt.Println(err)
	}
	myFigure := figure.NewColorFigure("SBScan", "doom", "red", true)
	myFigure.Print()
	fmt.Println("全称：SweetBaby，甜心宝贝扫描器")
	fmt.Println("Version <0.0.5> Made By InBug")

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
	flagSet.StringVarP(&p.SaveFile, "saveFile", "sf", "", "指定保存文件路径[以.xlsx结尾]")
	flagSet.StringVarP(&p.Host, "host", "h", "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8", "检测网段或者txt文件[以.txt结尾，一行一组回车换行]")
	flagSet.StringVarP(&p.Port, "port", "p", "tiny", "端口范围：tiny[精简]、normal[常用]、database[数据库]、caffe[咖啡厅/酒店/机场]、iot[物联网]、all[全部]、自定义")
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
	flagSet.IntVarP(&p.TimeOutScanWeak, "timeOutScanWeak", "tsw", 6, "爆破超时")
	flagSet.BoolVarP(&p.NoScanHost, "noScanHost", "nsh", false, "跳过主机存活检测")
	flagSet.BoolVarP(&p.NoScanWeak, "noScanWeak", "nsw", false, "跳过弱口令爆破")
	flagSet.BoolVarP(&p.NoScanPoc, "noScanPoc", "nsp", false, "跳过POC漏洞验证")
	flagSet.BoolVarP(&p.NoScanVul, "noScanVul", "nsv", false, "跳过高危系统漏洞探测")
	flagSet.StringVarP(&p.ServiceScanWeak, "serviceScanWeak", "ssw", "", "指定爆破协议：ssh,smb,snmp,sqlserver,mysql,mongodb,postgres,redis,ftp,clickhouse,elasticsearch，多个协议英文逗号分隔，默认全部")
	flagSet.StringVarP(&p.AUser, "aUser", "au", "", "追加弱口令账号字典[以.txt结尾]")
	flagSet.StringVarP(&p.APass, "aPass", "ap", "", "追加弱口令密码字典[以.txt结尾]")
	flagSet.StringVarP(&p.WUser, "wUser", "wu", "", "覆盖弱口令账号字典[以.txt结尾]")
	flagSet.StringVarP(&p.WPass, "wPass", "wp", "", "覆盖弱口令密码字典[以.txt结尾]")

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
