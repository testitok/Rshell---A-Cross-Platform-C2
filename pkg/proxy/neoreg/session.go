package neoreg

import (
	"BackendTemplate/pkg/command"
	"BackendTemplate/pkg/logger"
	"BackendTemplate/pkg/sendcommand"
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type Session struct {
	conn             net.Conn
	pSocket          net.Conn
	connectURLs      []string
	redirectURLs     []string
	fwdTarget        string
	forceRedirect    bool
	redirectURL      string
	connectClosed    bool
	sessionConnected bool
	mark             string
	target           string
	port             int
	mu               sync.Mutex
	client           *NeoregClient

	username string
	password string
}

func NewSession(conn net.Conn, c *NeoregClient, username, password string) *Session {
	s := &Session{
		conn:     conn,
		pSocket:  conn,
		client:   c,
		username: username,
		password: password,
	}
	return s
}

func randomChoice(slice []string) string {
	if len(slice) == 0 {
		return ""
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(slice))))
	return slice[n.Int64()]
}

func generateMark() string {
	uuid := make([]byte, 16)
	rand.Read(uuid)
	mark := base64.StdEncoding.EncodeToString(uuid)[:16]
	return mark
}

func (s *Session) urlSample() string {
	return randomChoice(s.connectURLs)
}

func (s *Session) sessionMark() string {
	s.mark = generateMark()
	return s.mark
}

func (s *Session) parseSocks5(sock net.Conn) bool {
	header := make([]byte, 2)
	if _, err := io.ReadFull(sock, header); err != nil {
		return false
	}
	ver := header[0]
	if ver != 0x05 {
		logger.Error("[SOCKS5] client version not 5")
		return false
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(sock, methods); err != nil {
		return false
	}

	var selected byte = 0xFF
	if s.username != "" {
		for _, m := range methods {
			if m == 0x02 {
				selected = 0x02
				break
			}
		}
	} else {
		for _, m := range methods {
			if m == 0x00 {
				selected = 0x00
				break
			}
		}
		if selected == 0xFF {
			for _, m := range methods {
				if m == 0x02 {
					selected = 0x02
					break
				}
			}
		}
	}

	if selected == 0xFF {
		sock.Write([]byte{0x05, 0xFF})
		return false
	}
	if _, err := sock.Write([]byte{0x05, selected}); err != nil {
		return false
	}

	if selected == 0x02 {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(sock, hdr); err != nil {
			return false
		}
		if hdr[0] != 0x01 {
			return false
		}
		ulen := int(hdr[1])
		uname := make([]byte, ulen)
		if _, err := io.ReadFull(sock, uname); err != nil {
			return false
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(sock, plenBuf); err != nil {
			return false
		}
		plen := int(plenBuf[0])
		passwd := make([]byte, plen)
		if _, err := io.ReadFull(sock, passwd); err != nil {
			return false
		}

		ok := (string(uname) == s.username && string(passwd) == s.password)
		var status byte = 0x01
		if ok {
			status = 0x00
		}
		if _, err := sock.Write([]byte{0x01, status}); err != nil {
			return false
		}
		if !ok {
			logger.Error("[SOCKS5] auth failed for user:", string(uname))
			return false
		}
	}

	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(sock, reqHdr); err != nil {
		return false
	}
	if reqHdr[0] != 0x05 {
		return false
	}
	cmd := reqHdr[1]
	atyp := reqHdr[3]

	var target string
	var targetPort uint16

	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(sock, ip); err != nil {
			return false
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(sock, portBuf); err != nil {
			return false
		}
		target = net.IP(ip).String()
		targetPort = binary.BigEndian.Uint16(portBuf)
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(sock, lenBuf); err != nil {
			return false
		}
		hostLen := int(lenBuf[0])
		host := make([]byte, hostLen)
		if _, err := io.ReadFull(sock, host); err != nil {
			return false
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(sock, portBuf); err != nil {
			return false
		}
		target = string(host)
		targetPort = binary.BigEndian.Uint16(portBuf)
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(sock, ip); err != nil {
			return false
		}
		portBuf := make([]byte, 2)
		if _, err := io.ReadFull(sock, portBuf); err != nil {
			return false
		}
		target = net.IP(ip).String()
		targetPort = binary.BigEndian.Uint16(portBuf)
	default:
		return false
	}

	if cmd == 0x02 {
		logger.Error("[SOCKS5] BIND not implemented")
		return false
	} else if cmd == 0x03 {
		logger.Error("[SOCKS5] UDP not implemented")
		return false
	} else if cmd == 0x01 {
		mark := s.setupRemoteSession(target, int(targetPort))
		if mark != "" {
			ip := net.ParseIP(target)
			if ip == nil || ip.To4() == nil {
				ip = net.ParseIP("127.0.0.1")
			}
			var ip4 [4]byte
			copy(ip4[:], ip.To4())
			resp := append([]byte{0x05, 0x00, 0x00, 0x01}, ip4[:]...)
			resp = append(resp, byte(targetPort>>8), byte(targetPort))
			sock.Write(resp)
			return true
		} else {
			ip := net.ParseIP("127.0.0.1")
			var ip4 [4]byte
			copy(ip4[:], ip.To4())
			resp := append([]byte{0x05, 0x01, 0x00, 0x01}, ip4[:]...) // general failure
			resp = append(resp, byte(targetPort>>8), byte(targetPort))
			sock.Write(resp)
			return false
		}
	}
	return false
}

func (s *Session) handleSocks(sock net.Conn) bool {
	return s.parseSocks5(sock)
}

func (s *Session) handleFwd(sock net.Conn) bool {
	if s.fwdTarget == "" {
		return false
	}
	host, portStr, _ := strings.Cut(s.fwdTarget, ":")
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	mark := s.setupRemoteSession(host, port)
	return mark != ""
}

func (s *Session) neoregRequest(info map[int][]byte, timeout time.Duration) (map[int][]byte, error) {

	body := encodeBody(info, s.client.Conf)

	queue := command.VarSocks5Queue.GetOrCreateQueue(s.client.Conf.Uid, fmt.Sprintf("%x", md5.Sum(body)))
	sendcommand.SendCommand(s.client.Conf.Uid, "socks5data "+string(body))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	select {
	case rawBody := <-queue:
		rdata := extractBody([]byte(rawBody))
		rinfo := decodeBody(rdata, s.client.Conf)

		if rinfo == nil {
			return nil, fmt.Errorf("response format error: %s", string(rawBody))
		}

		if string(rinfo[cmdStatus]) != "OK" && string(info[cmdCommand]) != "DISCONNECT" {
			logger.Error("Error: ", info[cmdCommand], s.target, s.port, rinfo[cmdError])
		}

		return rinfo, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *Session) setupRemoteSession(target string, port int) string {
	s.mark = s.sessionMark()
	s.target = target
	s.port = port

	info := map[int][]byte{
		cmdCommand: []byte("CONNECT"),
		cmdMark:    []byte(s.mark),
		cmdIP:      []byte(target),
		cmdPort:    []byte(fmt.Sprintf("%d", port)),
	}

	var rinfo map[int][]byte
	var err error

	timeout := 500 * time.Millisecond

	rinfo, err = s.neoregRequest(info, timeout)
	if err != nil {
		return s.mark
	}

	if string(rinfo[cmdStatus]) == "OK" {
		return s.mark
	}
	return ""
}

func (s *Session) closeRemoteSession() {
	s.mu.Lock()
	if s.connectClosed {
		s.mu.Unlock()
		return
	}
	s.connectClosed = true
	s.mu.Unlock()

	if s.pSocket != nil {
		s.pSocket.Close()
	}

	if s.mark != "" {
		info := map[int][]byte{
			cmdCommand: []byte("DISCONNECT"),
			cmdMark:    []byte(s.mark),
		}
		s.neoregRequest(info, 10*time.Second)
	}

}

func (s *Session) reader() {
	defer s.closeRemoteSession()

	info := map[int][]byte{
		cmdCommand: []byte("READ"),
		cmdMark:    []byte(s.mark),
	}
	n := 0

	for {
		if s.connectClosed || s.pSocket == nil {
			break
		}

		rinfo, err := s.neoregRequest(info, 30*time.Second)
		if err != nil || string(rinfo[cmdStatus]) != "OK" {
			break
		}

		data := rinfo[cmdData]
		dataLen := len(data)

		if dataLen == 0 {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		n++

		for len(data) > 0 && !s.connectClosed {
			written, err := s.pSocket.Write(data)
			if err != nil {
				return
			}
			data = data[written:]
		}

		if dataLen < 500 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (s *Session) writer() {
	defer s.closeRemoteSession()

	info := map[int][]byte{cmdCommand: []byte("FORWARD"), cmdMark: []byte(s.mark)}
	n := 0
	buf := make([]byte, 4096)

	for {
		if s.connectClosed {
			break
		}

		nr, err := s.pSocket.Read(buf)
		if err != nil {
			if err == io.EOF || errors.Is(err, net.ErrClosed) {
				break
			}
			break
		}

		if nr == 0 {
			continue
		}

		info[cmdData] = buf[:nr]
		rinfo, err := s.neoregRequest(info, 30*time.Second)
		if err != nil || string(rinfo[cmdStatus]) != "OK" {
			break
		}

		n++

		if nr < len(buf) {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func (s *Session) Run() {
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Session panicked:", r)
		}
	}()

	if s.fwdTarget != "" {
		s.sessionConnected = s.handleFwd(s.pSocket)
	} else {
		s.sessionConnected = s.handleSocks(s.pSocket)
	}

	if s.sessionConnected {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			s.reader()
		}()

		go func() {
			defer wg.Done()
			s.writer()
		}()

		wg.Wait()
	}
}

func extractBody(raw []byte) []byte {
	return raw
}
