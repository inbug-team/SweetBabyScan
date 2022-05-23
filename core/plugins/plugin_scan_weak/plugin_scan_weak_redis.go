package plugin_scan_weak

import (
	"SweetBabyScan/utils"
	"context"
	"fmt"
	"github.com/go-redis/redis/v8"
	"time"
)

func CheckRedis(ip, user, pwd string, port uint) bool {
	client := redis.NewClient(&redis.Options{
		Addr:        fmt.Sprintf(`%s:%d`, ip, port),
		Username:    user,
		Password:    pwd,
		DB:          0,
		DialTimeout: 6 * time.Second,
	})

	defer func() {
		err := client.Close()
		utils.PrintErr(err)
	}()

	ctx := context.Background()
	status, err := client.Ping(ctx).Result()
	if err != nil {
		return false
	}

	if status == "PONG" {
		return true
	}

	return false
}
