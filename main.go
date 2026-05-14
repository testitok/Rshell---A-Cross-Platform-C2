package main

import (
	"Rshell/pkg/database"
	"Rshell/pkg/encrypt"
	"Rshell/pkg/logger"
	"Rshell/pkg/routers"
	"Rshell/pkg/utils"
	"embed"
	"flag"
	"io/fs"
	"os"
	"strconv"
)

//go:embed dist
var embedFS embed.FS

func main() {
	utils.InitFunction()

	var bindPort = flag.Int("p", 8089, "Specify alternate port")
	flag.Parse()
	if *bindPort > 65535 || *bindPort < 0 {
		flag.Usage()
		os.Exit(0)
	}
	database.ConnectDateBase()
	defer database.Engine.Close()
	encrypt.GenerateKeyPair()

	database.Engine.Update(&database.Clients{Online: "2"})
	database.Engine.Update(&database.Listener{Status: 2})
	database.Engine.Update(&database.Socks5{Status: 2})
	database.Engine.Update(&database.WebDelivery{Status: 2})
	distFS, _ := fs.Sub(embedFS, "dist")
	staticFs, _ := fs.Sub(distFS, "static")
	r := routers.NewRouter(embedFS, staticFs)

	logger.Info("Listening on port " + strconv.Itoa(*bindPort))
	err := r.Run("0.0.0.0:" + strconv.Itoa(*bindPort))
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
