package plugin_sock5

import "github.com/net-byte/socks5-server/socks5"

func DoSock5(config socks5.Config) {
	socks5.StartServer(config)
}
