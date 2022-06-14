package plugin_port_map

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// 服务端配置
type ServerConfig struct {
	Key  string   `json:"key"`
	Port uint16   `json:"port"`
	Open []uint16 `json:"open"`
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

// 总配置
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
	// 空闲命令，什么也不做
	IDLE
	// 退出命令
	KILL
)

const (
	// IdleTime 心跳检测时间
	IdleTime = time.Second * 10
)

// KeyMd5 获取key的md5
func KeyMd5(key string) []byte {
	d5 := md5.New()
	d5.Write([]byte(key))
	return d5.Sum(nil)
}

// DoServer 服务端处理
func DoServer(config *ServerConfig) {
	if config == nil {
		return
	}
	clientMap := make(map[uint16]net.Conn)
	chanMap := make(map[uint16]chan net.Conn)
	// 守护客户端连接
	go func() {
		rt := make([]byte, 1)
		for {
			time.Sleep(IdleTime)
			for p, c := range clientMap {
				_, err := c.Write([]byte{IDLE})
				if err != nil {
					log.Println(err)
					delete(clientMap, p)
					if c != nil {
						c.Close()
					}
					log.Println("删除连接", p)
					continue
				}
				_, err = io.ReadAtLeast(c, rt, 1)
				if err != nil || rt[0] != Success {
					log.Println(err)
					delete(clientMap, p)
					if c != nil {
						c.Close()
					}
					log.Println("删除连接", p)
					continue
				}
			}

		}
	}()
	// 监听映射端口
	var doListen = func(port uint16) {
		chanMap[port] = make(chan net.Conn)
		lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%v", port))
		if err != nil {
			panic(err)
		}
		defer lis.Close()
		for {
			conn, err := lis.Accept()
			if err != nil {
				log.Println(err)
				continue
			}
			client := clientMap[port]
			if client != nil {
				// 新连接，发送命令
				client.Write([]byte{NewSocket})
				client.Write([]byte{uint8(port >> 8), uint8(port & 0xff)})
				chanMap[port] <- conn
			} else {
				conn.Close()
			}
		}
	}
	// 监听所有映射端口
	for _, p := range config.Open {
		go doListen(p)
	}
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%v", config.Port))
	if err != nil {
		panic(err)
	}
	defer lis.Close()
	var doConn = func(conn net.Conn) {
		var cmd = make([]byte, 1)
		io.ReadAtLeast(conn, cmd, 1)
		switch cmd[0] {
		case Start:
			// 初始化
			// 读取keyMd5
			rKeyMd5 := make([]byte, 16)
			io.ReadAtLeast(conn, rKeyMd5, 16)
			// 读取端口
			for {
				portBuf := make([]byte, 2)
				io.ReadAtLeast(conn, portBuf, 2)
				prt := uint16(portBuf[0])<<8 + uint16(portBuf[1])
				if prt == 0 {
					break
				}
				if _, ok := clientMap[prt]; ok {
					// 端口被用了
					conn.Write([]byte{Error})
					msg := []byte(fmt.Sprintf("端口(%v)占用！", prt))
					ml := uint16(len(msg))
					conn.Write([]byte{uint8(ml >> 8), uint8(ml & 0xff)})
					conn.Write(msg)
					conn.Close()
					return
				}
				clientMap[prt] = conn
				log.Println("启动端口", prt)
			}
			if !bytes.Equal(rKeyMd5, KeyMd5(config.Key)) {
				conn.Write([]byte{Error})
				msg := []byte("Key认证失败！")
				ml := uint16(len(msg))
				conn.Write([]byte{uint8(ml >> 8), uint8(ml & 0xff)})
				conn.Write(msg)
				conn.Close()
				return
			}
			conn.Write([]byte{Success})
		case NewConn:
			// 客户端新建立连接
			sport := make([]byte, 2)
			io.ReadAtLeast(conn, sport, 2)
			pt := (uint16(sport[0]) << 8) + uint16(sport[1])
			client := clientMap[pt]
			if client != nil {
				if rConn, ok := <-chanMap[pt]; ok {
					go io.Copy(rConn, conn)
					io.Copy(conn, rConn)
					conn.Close()
					rConn.Close()
				}
			} else {
				conn.Close()
			}
		case KILL:
			// 退出
			rKeyMd5 := make([]byte, 16)
			io.ReadAtLeast(conn, rKeyMd5, 16)
			if bytes.Equal(rKeyMd5, KeyMd5(config.Key)) {
				log.Println("退出！")
				conn.Write([]byte{Success})
				conn.Close()
				os.Exit(0)
			} else {
				conn.Write([]byte{Error})
				msg := []byte("Key认证失败！")
				ml := uint16(len(msg))
				conn.Write([]byte{uint8(ml >> 8), uint8(ml & 0xff)})
				conn.Write(msg)
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
	serverConn, err := net.Dial("tcp", config.Server)
	if err != nil {
		panic(err)
	}
	defer serverConn.Close()
	var portMap = make(map[uint16]string, len(config.Map))
	for _, m := range config.Map {
		portMap[m.Outer] = m.Inner
	}
	// 发送key
	serverConn.Write([]byte{Start})
	serverConn.Write(KeyMd5(config.Key))
	// 发送端口信息
	for p := range portMap {
		serverConn.Write([]byte{uint8(p >> 8), uint8(p & 0xff)})
	}
	serverConn.Write([]byte{0, 0})
	// 新建连接处理
	var doConn = func(conn net.Conn, sport uint16, sp []byte) {
		defer conn.Close()
		localConn, err := net.Dial("tcp", portMap[sport])
		if err != nil {
			log.Println(err)
			return
		}
		defer localConn.Close()
		conn.Write([]byte{NewConn})
		conn.Write(sp)
		go io.Copy(conn, localConn)
		io.Copy(localConn, conn)
	}
	// 进入指令读取循环
	var cmd = make([]byte, 1)
	for {
		serverConn.Read(cmd)
		switch cmd[0] {
		case Error:
			// 处理出错
			msgLen := make([]byte, 2)
			io.ReadAtLeast(serverConn, msgLen, 2)
			ml := int((uint16(msgLen[0]) << 8) + uint16(msgLen[1]))
			msg := make([]byte, ml)
			io.ReadAtLeast(serverConn, msg, ml)
			log.Println(string(msg))
			return
		case NewSocket:
			// 新建连接
			// 读取远端端口
			sp := make([]byte, 2)
			io.ReadAtLeast(serverConn, sp, 2)
			sport := uint16(sp[0])<<8 + uint16(sp[1])
			conn, err := net.Dial("tcp", config.Server)
			if err != nil {
				panic(err)
			}
			go doConn(conn, sport, sp)
		case IDLE:
			serverConn.Write([]byte{Success})
		}
	}
}

//func main() {
//	forever := make(chan bool)
//
//	var config Config
//	go DoServer(config.Server)
//	go DoClient(config.Client)
//
//	<-forever
//	log.Println("Bye~")
//}
