package proxy

import (
	"BackendTemplate/pkg/logger"
	"BackendTemplate/pkg/proxy/neoreg"
	"net"
	"sync"
)

var Socks5Serve = make(map[string]net.Listener)
var MuSocks5Serve sync.Mutex

func StartSocks5Proxy(port string, uid string, username string, password string) {
	conf, err := neoreg.NewConf(uid, "OEuFqQTgN9uBF0NQ")
	if err != nil {
		logger.Error(err.Error())
		return
	}
	c := &neoreg.NeoregClient{
		Conf: conf,
	}
	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logger.Error("Listen error:", err)
		return
	}
	defer listener.Close()
	MuSocks5Serve.Lock()
	Socks5Serve[port] = listener
	MuSocks5Serve.Unlock()
	logger.Info("SOCKS5 proxy listening on :", port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Accept error: ", err)
			break
		}
		session := neoreg.NewSession(conn, c, username, password)
		go session.Run()
	}
}
