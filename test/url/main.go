package main

import (
	"fmt"
	"net/url"
)

func GetUrl(link string) string {
	_url, err := url.Parse(link)
	if err != nil {
		return ""
	}
	if _url == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s", _url.Scheme, _url.Host)
}

func main() {
	link := "https://192.168.188.1:2000/1234/abcd"
	fmt.Println(GetUrl(link))
}
