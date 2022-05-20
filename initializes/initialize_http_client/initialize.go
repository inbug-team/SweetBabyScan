package initialize_http_client

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

var (
	HttpClient           *http.Client
	HttpClientNoRedirect *http.Client
	dialTimout           = 10 * time.Second
	keepAlive            = 15 * time.Second
	timeout              = 10 * time.Second
)

func InitHttpClient() {
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxConnsPerHost:     0,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 2000,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 10 * time.Second,
		DisableKeepAlives:   false,
	}

	HttpClient = &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}
	HttpClientNoRedirect = &http.Client{
		Transport:     tr,
		Timeout:       timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
}
