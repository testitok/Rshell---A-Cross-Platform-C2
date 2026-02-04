package database

import (
	"BackendTemplate/pkg/logger"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"

	_ "modernc.org/sqlite"
	"xorm.io/xorm"
)

var Engine *xorm.Engine
var DatabaseName string

type Users struct {
	Username string
	Password string
	//Email       string
	//Phone       string
	//Permissions int
}
type Clients struct {
	Uid        string
	FirstStart string
	ExternalIP string
	InternalIP string
	Username   string
	Computer   string
	Process    string
	Pid        string
	Address    string
	Arch       string
	Note       string
	Sleep      string
	Online     string
	Color      string
	PublicKey  string
}
type Notes struct {
	Uid  string
	Note string
}
type Shell struct {
	Uid          string
	ShellContent string
}
type Socks5 struct {
	Uid        string
	Type       string
	Socks5port string
	UserName   string
	Password   string
	Status     int
}

type Downloads struct {
	Uid            string
	FileName       string
	FilePath       string
	FileSize       int
	DownloadedSize int
}
type Listener struct {
	Type           string
	ListenAddress  string
	ConnectAddress string
	Status         int
}
type WebDelivery struct {
	ListenerConfig string
	OS             string
	Arch           string
	ListeningPort  string
	Status         int
	ServerAddress  string
	FileName       string
	Pass           string
}
type Settings struct {
	Name  string
	Value string
}
type Key struct {
	PublicKey  string
	PrivateKey string
}

func ConnectDateBase() {
	var err error
	// 获取当前程序所在目录
	exePath, err := os.Executable()
	if err != nil {
		log.Fatalf("获取程序路径失败: %v", err)
	}

	// 获取程序所在目录
	exeDir := filepath.Dir(exePath)

	// 设置数据库路径为程序所在目录下的 database.db
	DatabaseName = filepath.Join(exeDir, "database.db")

	Engine, err = xorm.NewEngine("sqlite", DatabaseName)
	if err != nil {
		log.Fatalf("连接sqlite数据库失败: %v", err)
	}
	err = Engine.Sync2(new(Users), new(Clients), new(Notes), new(Shell), new(Downloads), new(Listener), new(WebDelivery), new(Socks5), new(Settings), new(Key))
	if err != nil {
		log.Fatalf("初始化数据库失败: %v", err)
	}
	var user Users
	exists, err := Engine.Where("username = ?", "admin").Get(&user)
	if !exists {
		// 如果不存在 admin 用户，插入默认的 admin 用户
		defaultUser := &Users{
			Username: "admin",
			Password: "admin123",
			//Email:       "admin@example.com",
			//Phone:       "1234567890",
			//Permissions: 1,
		}

		err = InsertData(Engine, defaultUser)
		if err != nil {
			logger.Error(fmt.Sprintf("插入默认 admin 用户失败: %v", err))
			os.Exit(0)
		}
	}
	var Setting Settings
	exists, err = Engine.Where("name=?", "wecom").Get(&Setting)
	if !exists {
		defaultSetting := &Settings{
			Name:  "wecom",
			Value: "",
		}
		err = InsertData(Engine, defaultSetting)
		if err != nil {
			logger.Error(err.Error())
			os.Exit(0)
		}
	}
}

// InsertData 函数用于插入任意表的数据
func InsertData(engine *xorm.Engine, table interface{}) error {
	// 使用反射获取表的信息
	valueOfTable := reflect.ValueOf(table)
	if valueOfTable.Kind() != reflect.Ptr || valueOfTable.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("table parameter must be a pointer to a struct")
	}

	// 同步数据库结构
	err := engine.Sync2(table)
	if err != nil {
		return fmt.Errorf("failed to sync database structure: %v", err)
	}

	// 插入数据
	_, err = engine.Insert(table)
	if err != nil {
		return fmt.Errorf("failed to insert data: %v", err)
	}

	return nil
}
func ExecuteSQL(engine *xorm.Engine, sql string, args ...interface{}) error {
	_, err := engine.Exec(sql, args)
	if err != nil {
		return fmt.Errorf("failed to execute SQL: %v", err)
	}
	return nil
}
func QuerySQL(engine *xorm.Engine, sql string, args ...interface{}) ([]map[string]string, error) {
	results, err := engine.QueryString(sql, args)
	if err != nil {
		return nil, fmt.Errorf("failed to query SQL: %v", err)
	}
	return results, nil
}
