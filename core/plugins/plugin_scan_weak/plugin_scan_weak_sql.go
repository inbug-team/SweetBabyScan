package plugin_scan_weak

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

func CheckSQL(hostType, ip, user, pwd string, port int) bool {

	connectStr := ""
	var err error
	switch hostType {
	case "mysql":
		connectStr = fmt.Sprintf(
			"%s:%s@tcp(%s:%d)/%s?timeout=%ds",
			user, pwd, ip, port, "", 6,
		)
		_, err = gorm.Open(mysql.Open(connectStr), &gorm.Config{Logger: nil})
	case "postgres":
		connectStr = fmt.Sprintf(
			"host=%s port=%d user=%s dbname=%s sslmode=disable password=%s",
			ip, port, user, "", pwd,
		)
		_, err = gorm.Open(postgres.Open(connectStr), &gorm.Config{Logger: nil})
	case "mssql":
		connectStr = fmt.Sprintf(
			"sqlserver://%s:%s@%s:%d?database=%s",
			user, pwd, ip, port, "",
		)
		_, err = gorm.Open(sqlserver.Open(connectStr), &gorm.Config{Logger: nil})
	}

	if err != nil {
		return false
	}
	return true
}
