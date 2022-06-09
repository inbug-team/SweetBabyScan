package main

import (
	"fmt"
	"github.com/inbug-team/SweetBabyScan/initializes/initialize_http_client"
	"net/http"
)

func init() {
	initialize_http_client.InitHttpClient()
}

func main() {
	client := initialize_http_client.HttpClient
	req, err := http.NewRequest("GET", "http://192.168.188.155:8983/", nil)
	if err != nil {
		//fmt.Println(err)
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		//fmt.Println(err)
	}

	fmt.Println(resp.StatusCode)
	respUrl, err := resp.Location()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(respUrl.String())
}
