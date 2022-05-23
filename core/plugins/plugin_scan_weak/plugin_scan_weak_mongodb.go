package plugin_scan_weak

import (
	"context"
	"fmt"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

func CheckMongoDB(ip, user, pwd string, port uint) bool {
	// 设置客户端连接配置
	clientOptions := options.Client().ApplyURI(
		fmt.Sprintf(`mongodb://%s:%s@%s:%d/admin`, user, pwd, ip, port),
	).SetConnectTimeout(6 * time.Second)

	// 连接到MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return false
	}

	// 检查连接
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return false
	}

	return true
}
