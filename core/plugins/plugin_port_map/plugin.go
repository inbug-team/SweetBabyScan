package plugin_port_map

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// 服务端配置
type ServerConfig struct {
	Key  string `json:"key"`
	Port uint16 `json:"port"`
}

// 客户端map配置
type ClientMapConfig struct {
	Inner string `json:"inner"`
	Outer uint16 `json:"outer"`
}

// 客户端配置
type ClientConfig struct {
	Key    string            `json:"key"`
	Server string            `json:"server"`
	Map    []ClientMapConfig `json:"map"`
}

// 配置
type Config struct {
	Server *ServerConfig `json:"server"`
	Client *ClientConfig `json:"client"`
}

const (
	_ uint8 = iota
	// 第一次连接服务器
	Start
	// 新连接
	NewSocket
	// 新连接发送到服务端命令
	NewConn
	// 处理失败
	Error
	// 处理成功
	Success
	// 空闲命令 什么也不做
	Idle
	// 退出命令
	Kill
)

const (
	// 断线重连时间
	RetryTime          = time.Second
	TcpKeepAlivePeriod = 30 * time.Second
)

func Recover() {
	if err := recover(); err != nil {
		log.Println(err)
	}
}

type Resource struct {
	Listener net.Listener
	ConnChan chan net.Conn
	Running  bool
}

// 服务端处理
func DoServer(config *ServerConfig) {
	if config == nil {
		return
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%v", config.Port))
	if err != nil {
		log.Println("Initialization error", err)
		return
	}
	defer lis.Close()
	// 端口-资源对应
	var resourceMap = make(map[uint16]*Resource)
	var resourceMu sync.Mutex
	// 处理对客户端的监听
	var doListen = func(ctx context.Context, clientConn net.Conn, port uint16) {
		if resourceMap[port] == nil {
			return
		}
		defer func() {
			Recover()
			defer Recover()
			close(resourceMap[port].ConnChan)
			resourceMap[port].Listener.Close()
			resourceMu.Lock()
			delete(resourceMap, port)
			resourceMu.Unlock()
			log.Println("关闭端口", port)
		}()
		log.Println("启动端口", port)
		var rsc = resourceMap[port]
		var buffer bytes.Buffer
		buffer.Write([]byte{NewSocket})
		buffer.Write([]byte{uint8(port >> 8), uint8(port & 0xff)})
		openCmd := buffer.Bytes()
		buffer.Reset()
		go func() {
			defer Recover()
			for {
				outConn, err := rsc.Listener.Accept()
				if err != nil {
					return
				}
				// 通知客户端建立连接
				clientConn.Write(openCmd)
				rsc.ConnChan <- outConn
			}
		}()
		<-ctx.Done()
	}
	// 处理客户端新连接
	var doConn = func(conn net.Conn) {
		defer Recover()
		defer conn.Close()
		var cmd = make([]byte, 1)
		if _, err = io.ReadAtLeast(conn, cmd, 1); err != nil {
			return
		}
		switch cmd[0] {
		case Start:
			// 初始化
			infoLen := make([]byte, 8)
			if _, err = io.ReadAtLeast(conn, infoLen, 8); err != nil {
				return
			}
			var iLen = (uint64(infoLen[0]) << 56) | (uint64(infoLen[1]) << 48) | (uint64(infoLen[2]) << 40) | (uint64(infoLen[3]) << 32) | (uint64(infoLen[4]) << 24) | (uint64(infoLen[5]) << 16) | (uint64(infoLen[6]) << 8) | (uint64(infoLen[7]))
			if iLen > 1024*1024 {
				// 限制消息最大内存使用量 1M
				return
			}
			var clientInfo = make([]byte, iLen)
			if _, err = io.ReadAtLeast(conn, clientInfo, int(iLen)); err != nil {
				return
			}
			var clientCfg ClientConfig
			if nil != json.Unmarshal(clientInfo, &clientCfg) {
				return
			}
			if clientCfg.Key != config.Key {
				conn.Write([]byte{Error})
				return
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// 打开端口
			for _, cc := range clientCfg.Map {
				clientServer, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%v", cc.Outer))
				if err != nil {
					log.Println("启动端口失败，错误原因", err)
					conn.Write([]byte{Error})
					return
				}
				resourceMu.Lock()
				resourceMap[cc.Outer] = &Resource{
					Listener: clientServer,
					ConnChan: make(chan net.Conn),
					Running:  true,
				}
				resourceMu.Unlock()
				go doListen(ctx, conn, cc.Outer)
			}
			conn.Write([]byte{Success})
			for {
				n, err := conn.Read(cmd)
				if err != nil {
					return
				}
				if n != 0 {
					switch cmd[0] {
					case Kill:
						return
					case Idle:
						continue
					}
				}
			}
		case NewConn:
			// 客户端新建立连接
			sport := make([]byte, 2)
			io.ReadAtLeast(conn, sport, 2)
			pt := (uint16(sport[0]) << 8) + uint16(sport[1])
			client := resourceMap[pt]
			if client != nil {
				if rConn, ok := <-client.ConnChan; ok {
					go io.Copy(rConn, conn)
					io.Copy(conn, rConn)
					conn.Close()
					rConn.Close()
				}
			} else {
				conn.Close()
			}
		default:
			conn.Close()
		}
	}

	for {
		remoteConn, err := lis.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go doConn(remoteConn)
	}

}

// DoClient 客户端处理
func DoClient(config *ClientConfig) {
	if config == nil {
		return
	}
	var portMap = make(map[uint16]string, len(config.Map))
	for _, m := range config.Map {
		portMap[m.Outer] = m.Inner
	}
	var isContinue = true
	// 新建连接处理
	var doConn = func(conn net.Conn, sport uint16, sp []byte) {
		defer Recover()
		defer conn.Close()
		localConn, err := net.Dial("tcp", portMap[sport])
		localConn.(*net.TCPConn).SetKeepAlive(true)
		localConn.(*net.TCPConn).SetKeepAlivePeriod(TcpKeepAlivePeriod)
		if err != nil {
			log.Println(err)
			return
		}
		defer localConn.Close()
		var buffer bytes.Buffer
		buffer.Write([]byte{NewConn})
		buffer.Write(sp)
		conn.Write(buffer.Bytes())
		buffer.Reset()
		go io.Copy(conn, localConn)
		io.Copy(localConn, conn)
	}
	for isContinue {
		func() {
			defer Recover()
			defer time.Sleep(RetryTime)
			log.Println("正在连接服务器...")
			serverConn, err := net.Dial("tcp", config.Server)
			if err != nil {
				return
			}
			defer serverConn.Close()
			log.Println("连接服务器成功")
			clientInfo, err := json.Marshal(config)
			// 添加字节缓冲
			var buffer bytes.Buffer
			// 发送客户端信息
			buffer.Write([]byte{Start})
			binary.Write(&buffer, binary.BigEndian, uint64(len(clientInfo)))
			buffer.Write(clientInfo)
			serverConn.Write(buffer.Bytes())
			buffer.Reset()
			// 读取返回信息
			// SUCCESS / ERROR
			var recvCmd = make([]byte, 1)
			io.ReadAtLeast(serverConn, recvCmd, 1)
			if recvCmd[0] != Success {
				// 密码错误
				log.Println("鉴权失败")
				isContinue = false
				return
			}
			log.Println("认证成功")
			for _, cc := range config.Map {
				log.Printf("%v->:%v\n", cc.Inner, cc.Outer)
			}
			recvCmd[0] = Idle
			// 进入指令读取循环
			for {
				_, err = serverConn.Read(recvCmd)
				if err != nil {
					return
				}
				switch recvCmd[0] {
				case NewSocket:
					// 新建连接
					// 读取远端端口
					sp := make([]byte, 2)
					io.ReadAtLeast(serverConn, sp, 2)
					sport := uint16(sp[0])<<8 + uint16(sp[1])
					conn, err := net.Dial("tcp", config.Server)
					if err != nil {
						return
					}
					go doConn(conn, sport, sp)
				case Idle:
					_, err := serverConn.Write([]byte{Success})
					if err != nil {
						return
					}
				}
			}
		}()
	}
}
