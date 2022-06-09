# SweetBabyScan

轻量级内网资产探测漏洞扫描工具

## 简介

甜心宝贝是一款支持弱口令爆破的内网资产探测漏洞扫描工具，集成了Xray与Nuclei的Poc

### 工具定位

内网资产探测、通用漏洞扫描、弱口令爆破

### 工具截图

工具根据系统自动下载对应版本的Chromium
![1](img/1.png)
![2](img/2.png)
![3](img/3.png)
![4](img/4.png)
![5](img/5.png)
![13](img/13.png)
![14](img/14.png)
![17](img/17.png)
调高探测与扫描并发

```
./SbScan -h 192.168.0.0/16 -wsh 500 --wsp 500
```

![6](img/6.png)
![7](img/7.png)
![8](img/8.png)

端口扫描可以写端口号、端口范围或者常用端口类型

```
./SbScan -h 192.168.188.0/24 -p 80,22,81-89
```

![9](img/9.png)
![10](img/10.png)

列出weblogic漏洞对应的poc

```
./SbScan --lpn --fpn weblogic
```

![15](img/15.png)

列出thinkphp漏洞对应的poc
![16](img/16.png)

### 一、编译

- 递归克隆项目，获取最新poc

```shell
git clone https://github.com/inbug-team/SweetBabyScan.git --recursive
```

- 初始化module

```shell
go mod tidy
go mod vendor
```

- Windows

```shell
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -trimpath -o SbScan.exe

set GOOS=windows
set GOARCH=386
go build -ldflags="-s -w" -trimpath -o SbScan.exe
```

- Mac or Linux

```shell
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o SbScan
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -trimpath -o SbScan
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o SbScan
GOOS=linux GOARCH=386 go build -ldflags="-s -w" -trimpath -o SbScan
```

### 二、运行

- 自动扫描

> ./SbScan

- 根据指定IP段扫描

> ./SbScan -h=192.168.188.1/24

- 根据指定IP+端口扫描

> ./SbScan -h=192.168.188.1/24 -p=tiny

> ./SbScan -h=192.168.188.1/24,10.0.0.1/16 -p=22,80,443

- 修改并发提高性能

> ./SbScan -wsh=2048 -wsp=1024 -h=192.168.188.1/24,10.0.0.1/16 -p=22,80,443

- 跳过主机存活检测（nsh）、POC漏洞探测（nsp）、弱口令爆破（nsw）、高危漏洞探测（nsv）

> ./SbScan -h=192.168.188.1/24 -p=22,80 --nsh --nsp --nsw --nsv

- 指定IP文件、密码文件、账号文件、输出excel文件、指定爆破协议

> ./SbScan -h=ip.txt -wp=pass.txt -wu=user.txt -oe=test.xlsx -ot=test.txt -ssw=redis,ssh,mysql

- 弱口令生成器（覆盖模式iwp、追加模式iap）

> ./SbScan -h=192.168.188.1/24 -iwp -pp=test,Test -pc=@ -ps=123


### 三、参数

- 查看参数帮助命令

> ./SbScan --help

```text
Usage:
  ./SbScan [flags]

Flags:
   -il, -isLog                         是否显示日志 (default true)
   -is, -isScreen                      是否启用截图 (default true)
   -oe, -outputExcel string            指定保存excel文件路径[以.xlsx结尾]
   -ot, -outputTxt string              指定保存txt文件路径[以.txt结尾]
   -h, -host string                    检测网段或者txt文件[以.txt结尾，一行一组回车换行] (default "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8")
   -p, -port string                    端口范围：tiny[精简]、web[WEB服务]、normal[常用]、database[数据库]、caffe[咖啡厅/酒店/机场]、iot[物联网]、all[全部]、自定义 (default "web")
   -pt, -protocol string               端口范围：tcp、udp、tcp+udp (default "tcp+udp")
   -hb, -hostBlack string              排除网段
   -msh, -methodScanHost string        验存方式：PING、ICMP (default "PING")
   -wsh, -workerScanHost int           存活并发 (default 250)
   -tsh, -timeOutScanHost int          存活超时 (default 3)
   -r, -rarity int                     优先级 (default 10)
   -wsp, -workerScanPort int           扫描并发 (default 250)
   -tspc, -timeOutScanPortConnect int  端口扫描连接超时 (default 3)
   -tsps, -timeOutScanPortSend int     端口扫描发包超时 (default 3)
   -tspr, -timeOutScanPortRead int     端口扫描读取超时 (default 3)
   -inpo, -isNULLProbeOnly             使用空探针，默认使用自适应探针
   -iuap, -isUseAllProbes              使用全量探针，默认使用自适应探针
   -wss, -workerScanSite int           爬虫并发 (default 16)
   -tss, -timeOutScanSite int          爬虫超时 (default 3)
   -ts, -timeOutScreen int             截图超时 (default 60)
   -lpn, -listPocNuclei                是否列举Poc Nuclei
   -lpx, -ListPocXray                  是否列举Poc Xray
   -fpn, -filterPocName string         筛选POC名称，多个关键字英文逗号隔开
   -fvl, -filterVulLevel string        筛选POC严重等级：critical[严重] > high[高危] > medium[中危] > low[低危] > info[信息]、unknown[未知]、all[全部]，多个关键字英文逗号隔开
   -tspn, -timeOutScanPocNuclei int    PocNuclei扫描超时 (default 6)
   -wsPoc, -workerScanPoc int          Poc并发 (default 100)
   -gsw, -groupScanWeak int            爆破分组 (default 20)
   -wsw, -workerScanWeak string        爆破并发，键值对形式，英文逗号分隔 (default "ssh:1,smb:1,snmp:1,sqlserver:4,mysql:4,mongodb:4,postgres:4,redis:6,ftp:1,clickhouh:4")
   -tsw, -timeOutScanWeak int          爆破超时 (default 6)
   -nsh, -noScanHost                   跳过主机存活检测
   -nsw, -noScanWeak                   跳过弱口令爆破
   -nsp, -noScanPoc                    跳过POC漏洞验证
   -nsv, -noScanVul                    跳过高危系统漏洞探测
   -ssw, -serviceScanWeak string       指定爆破协议：ssh,smb,snmp,sqlserver,mysql,mongodb,postgres,redis,ftp,clickhouse,elasticsearch，多个协议英文逗号分隔，默认全部
   -au, -aUser string                  追加弱口令账号字典[以.txt结尾]
   -ap, -aPass string                  追加弱口令密码字典[以.txt结尾]
   -wu, -wUser string                  覆盖弱口令账号字典[以.txt结尾]
   -wp, -wPass string                  覆盖弱口令密码字典[以.txt结尾]
   -iap, -isAPass                      是否追加弱口令生成器
   -iwp, -isWPass                      是否覆盖弱口令生成器
   -pp, -passwordPrefix string         密码前缀，多个英文逗号分隔
   -pc, -passwordCenter string         密码中位，多个英文逗号分隔
   -ps, -passwordSuffix string         密码后缀，多个英文逗号分隔
```

### 四、更新日志
<details>
  <summary>更新日志👇🏻点击展开</summary>

```text
2022-06-09（v0.0.6）
    [+]1.弱口令生成器
    [+]2.支持excel+txt文件导出
    [+]3.http跳转资产探测
    [+]4.更新nuclei
    [+]5.ICMP自动检测，无权限切换为PING，默认ICMP
    [x]6.IP洗牌改成4字节整型，降低占用内存
    [x]7.修复弱口令爆破并发过高丢包bug，协程泄漏问题，增加自定义指定协议并发数
2022-06-06（v0.0.5）
    [+]1.自定义输出文件
    [+]2.自定义爆破协议
    [+]3.自定义爆破账号密码文件（支持追加模式和覆盖模式）
    [+]4.自定义IP文件
2022-06-01（v0.0.4）
    [x]1.修复POC Xray扫描引擎
    [x]2.修复外网是否可以达？可达下载chrome并截图
    [x]3.修复临时文件无法删除bug
    [+]4.优化进度条
    [+]5.新增跳过（主机存活、弱口令、POC、高危漏洞）参数
2022-05-29（v0.0.3）
    [x]1.修改弱口令爆破阻塞bug
    [x]2.优化进度条显示
2022-05-28（v0.0.2）
    [+]1.网卡识别
    [+]2.域控识别
    [+]3.MS17010漏洞探测
    [+]4.SMBGhost漏洞探测
    [+]5.POC Xray V2漏洞探测
    [+]6.POC Nuclei V2漏洞探测
    [+]7.弱口令爆破
        * FTP爆破
        * SSH爆破
        * SMB爆破
        * SNMP爆破
        * Redis爆破
        * MongoDB爆破
        * MySQL爆破
        * SQLServer爆破
        * PostGreSQL爆破
        * ElasticSearch爆破
    [+]8.结果存储到Excel
2022-05-20（v0.0.1）
    [+]1.主机存活检测（PING｜ICMP）
    [+]2.端口服务扫描（高精度探针指纹识别）
    [+]3.网站指纹爬虫（站点截图、CMS识别）
```

</details>

### 五、参考项目

- 致谢🙏🙏🙏

```text
1.nuclei：https://github.com/projectdiscovery/nuclei
2.xray：https://github.com/chaitin/xray
```

### Star Chart

[![Stargazers over time](https://starchart.cc/inbug-team/SweetBabyScan.svg)](https://starchart.cc/inbug-team/SweetBabyScan)

**官网**
https://www.inbug.org

如有BUG优先提交issues:
https://github.com/inbug-team/SweetBabyScan/issues

如有更好的功能建议，欢迎添加微信，好的功能建议采纳后，将会更新到下一个版本中。
![-Wechat](img/WeChat.png)

同时也可通过公众号联系：
![-w784](img/InBug.bmp)
