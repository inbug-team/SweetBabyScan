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

- Linux & Mac临时修改最大打开文件限制，提升并发性能

> ulimit -n 65535 && ./SbScan -wsh=2048 -wsp=1024 -h=192.168.188.1/24,10.0.0.1/16 -p=22,80,443

### 三、参数

- 查看参数帮助命令

> ./SbScan --help

```text
Usage:
  ./SweetBabyScan [flags]

Flags:
   -l, -lang string                    语言 (default "zh-cn")
   -il, -isLog                         是否显示日志 (default true)
   -is, -isScreen                      是否启用截图 (default true)
   -h, -host string                    检测网段 (default "192.168.0.0/16,172.16.0.0/12,10.0.0.0/8")
   -p, -port string                    端口范围：tiny[精简]、normal[常用]、database[数据库]、caffe[咖啡厅/酒店/机场]、iot[物联网]、all[全部]、自定义 (default "tiny")
   -pt, -protocol string               端口范围：tcp、udp、tcp+udp (default "tcp+udp")
   -hb, -hostBlack string              排除网段
   -msh, -methodScanHost string        验存方式：PING、ICMP (default "PING")
   -if, -iFace string                  出口网卡
   -wsh, -workerScanHost int           存活并发 (default 250)
   -tsh, -timeOutScanHost int          存活超时 (default 3)
   -r, -rarity int                     优先级 (default 10)
   -wsp, -workerScanPort int           扫描并发 (default 250)
   -tspc, -timeOutScanPortConnect int  端口扫描连接超时 (default 3)
   -tsps, -timeOutScanPortSend int     端口扫描发包超时 (default 3)
   -tspr, -timeOutScanPortRead int     端口扫描读取超时 (default 3)
   -inpo, -isNULLProbeOnly             使用空探针
   -iuap, -isUseAllProbes              使用全量探针
   -wss, -workerScanSite int           爬虫并发 (default 16)
   -tss, -timeOutScanSite int          爬虫超时 (default 3)
   -ts, -timeOutScreen int             截图超时 (default 60)
   -lpn, -listPocNuclei                是否列举Poc Nuclei
   -lpx, -ListPocXray                  是否列举Poc Xray
   -fpn, -filterPocName string         筛选POC名称，多个关键字英文逗号隔开
   -fvl, -filterVulLevel string        筛选POC严重等级：critical[严重] > high[高危] > medium[中危] > low[低危] > info[信息]、unknown[未知]、all[全部]，多个关键字英文逗号隔开
   -tspn, -timeOutScanPocNuclei int    PocNuclei扫描超时 (default 6)
   -wsPoc, -workerScanPoc int          Poc并发 (default 100)
   -wsw, -workerScanWeak int           爆破并发 (default 20)
   -gsw, -groupScanWeak int            爆破分组 (default 10)
```

### 四、更新日志

```text
2022-05-28（v0.0.2）
    [+]4.网卡识别
    [+]5.域控识别
    [+]6.MS17010漏洞探测
    [+]7.SMBGhost漏洞探测
    [+]8.POC Xray V2漏洞探测
    [+]9.POC Nuclei V2漏洞探测
    [+]10.弱口令爆破
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
    [+]11.结果存储到Excel
2022-05-20（v0.0.1）
    [+]1.主机存活检测（PING｜ICMP）
    [+]2.端口服务扫描（高精度探针指纹识别）
    [+]3.网站指纹爬虫（站点截图、CMS识别）
```

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

同时也可通过公众号联系：
![-w784](img/InBug.bmp)
