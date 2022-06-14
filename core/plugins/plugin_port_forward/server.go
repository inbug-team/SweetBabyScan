package plugin_port_forward

import (
	"fmt"
	"io"
	"net"
)

func handleIO(connClient net.Conn, host, source string) {
	connRemote, err := net.Dial("tcp", source)
	if err != nil {
		fmt.Println(fmt.Sprintf("[端口转发]%s连接目标失败，错误原因：(%s)", source, err.Error()))
		return
	}
	fmt.Println(fmt.Sprintf("[端口转发]%s <-> %s建立连接成功", host, source))
	defer connClient.Close()
	defer connRemote.Close()
	go io.Copy(connRemote, connClient)
	io.Copy(connClient, connRemote)
}

// 服务端隧道
func StartPortForward(port int, source string) {
	if port <= 0 || port >= 65535 {
		fmt.Println(fmt.Sprintf("[端口转发]端口%d所在范围错误，请从1~65535之间选择", port))
		return
	}

	if source == "" {
		fmt.Println("[端口转发]目标转发主机必填，格式：IP:端口")
		return
	}

	host := fmt.Sprintf(`0.0.0.0:%d`, port)
	fmt.Println(fmt.Sprintf("[端口转发]%s <-> %s开始建立连接", host, source))
	// 监听端口
	server, errL := net.Listen("tcp", host)
	if errL != nil {
		fmt.Println(fmt.Sprintf("[端口转发]%s监听端口失败，错误原因：(%s)", host, errL.Error()))
		return
	}
	defer server.Close()

	// 接收连接
	for {
		connClient, errA := server.Accept()
		if errA != nil {
			fmt.Println(fmt.Sprintf("[端口转发]%s接收连接失败，错误原因：(%s)", host, errA.Error()))
			return
		}
		go handleIO(connClient, host, source)
	}

}
