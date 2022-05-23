package plugin_scan_weak

import (
	"context"
	"fmt"
	"github.com/olivere/elastic/v7"
)

func CheckElasticSearch(ip, user, pwd string, port uint) bool {
	flag := false

	client, err := elastic.NewClient(elastic.SetURL(fmt.Sprintf("http://%v:%v", ip, port)),
		elastic.SetBasicAuth(user, pwd),
	)
	if err == nil {
		ctx := context.Background()
		_, _, err = client.Ping(fmt.Sprintf("http://%v:%v", ip, port)).Do(ctx)
		if err == nil {
			flag = true
		}
	}
	return flag
}
