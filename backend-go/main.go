package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	dashMu   sync.Mutex
	dashConn net.Conn

	sessionMu sync.Mutex
	sessions  = map[string]*tcpSession{}

	allowedFiles = map[string]bool{
		"dashboard.html":    true,
		"backend.py":        true,
		"backend.ps1":       true,
		"backend.txt":       true,
		"backend-b64.txt":       true,
		"socks-bridge.txt":      true,
		"socks-bridge.ps1":      true,
		"socks-bridge.py":       true,
		"socks-bridge-b64.txt":  true,
		"port-forward.txt":      true,
		"port-forward-b64.txt":  true,
	}
)

type tcpSession struct {
	conn net.Conn
	mu   sync.Mutex
}

// --- WebSocket framing (raw, no library) ---

func wsAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func wsWriteFrame(conn net.Conn, payload []byte) error {
	frame := []byte{0x81}
	n := len(payload)
	if n < 126 {
		frame = append(frame, byte(n))
	} else if n < 65536 {
		frame = append(frame, 126)
		frame = append(frame, byte(n>>8), byte(n&0xFF))
	} else {
		frame = append(frame, 127)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(n))
		frame = append(frame, b...)
	}
	frame = append(frame, payload...)
	_, err := conn.Write(frame)
	return err
}

func wsWriteJSON(conn net.Conn, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return wsWriteFrame(conn, data)
}

func wsReadFrame(conn net.Conn) ([]byte, int, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, 0, err
	}

	opcode := int(header[0] & 0x0F)
	if opcode == 8 {
		return nil, 8, nil
	}

	masked := (header[1] & 0x80) != 0
	length := uint64(header[1] & 0x7F)

	if length == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, 0, err
		}
		length = uint64(binary.BigEndian.Uint16(ext))
	} else if length == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(conn, ext); err != nil {
			return nil, 0, err
		}
		length = binary.BigEndian.Uint64(ext)
	}

	var mask []byte
	if masked {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(conn, mask); err != nil {
			return nil, 0, err
		}
	}

	if length == 0 {
		return []byte{}, opcode, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, 0, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}

	return payload, opcode, nil
}

// --- Send to dashboard ---

func sendToDash(msg map[string]interface{}) {
	dashMu.Lock()
	c := dashConn
	dashMu.Unlock()
	if c == nil {
		return
	}
	if err := wsWriteJSON(c, msg); err != nil {
		log.Printf("dashboard send error: %v", err)
	}
}

// --- DNS with DoH fallback ---

func resolveHost(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err == nil && len(ips) > 0 {
		log.Printf("DNS [system] %s -> %s", host, ips[0])
		return ips[0], nil
	}
	log.Printf("DNS [system] %s failed: %v, trying DoH", host, err)

	dohURL := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", url.QueryEscape(host))
	req, _ := http.NewRequest("GET", dohURL, nil)
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("system DNS and DoH both failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))

	var result struct {
		Answer []struct {
			Data string `json:"data"`
			Type int    `json:"type"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("DoH parse error: %v", err)
	}
	for _, a := range result.Answer {
		if a.Type == 1 {
			log.Printf("DNS [DoH] %s -> %s", host, a.Data)
			return a.Data, nil
		}
	}
	return "", fmt.Errorf("no A record for %s via DoH", host)
}

// --- TCP tunnel ---

func handleTCPConnect(session, host string, port int) {
	resolved, err := resolveHost(host)
	if err != nil {
		sendToDash(map[string]interface{}{"type": "error", "session": session, "msg": err.Error()})
		log.Printf("DNS error [%s]: %v", session, err)
		return
	}
	addr := fmt.Sprintf("%s:%d", resolved, port)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		sendToDash(map[string]interface{}{"type": "error", "session": session, "msg": err.Error()})
		log.Printf("TCP error [%s]: %v", session, err)
		return
	}

	s := &tcpSession{conn: conn}
	sessionMu.Lock()
	sessions[session] = s
	sessionMu.Unlock()

	sendToDash(map[string]interface{}{"type": "connected", "session": session})
	log.Printf("TCP [%s] -> %s", session, addr)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				b64 := base64.StdEncoding.EncodeToString(buf[:n])
				sendToDash(map[string]interface{}{
					"type":    "data",
					"session": session,
					"data":    b64,
				})
			}
			if err != nil {
				break
			}
		}

		sessionMu.Lock()
		delete(sessions, session)
		sessionMu.Unlock()

		sendToDash(map[string]interface{}{"type": "closed", "session": session})
		log.Printf("TCP closed: %s", session)
	}()
}

func handleTCPData(session, b64data string) {
	sessionMu.Lock()
	s, ok := sessions[session]
	sessionMu.Unlock()
	if !ok {
		return
	}
	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.conn.Write(data)
	s.mu.Unlock()
}

func handleTCPClose(session string) {
	sessionMu.Lock()
	s, ok := sessions[session]
	if ok {
		delete(sessions, session)
	}
	sessionMu.Unlock()
	if ok {
		s.conn.Close()
		sendToDash(map[string]interface{}{"type": "closed", "session": session})
	}
}

// --- HTTP fetch ---

func handleFetch(id, rawURL, method, headers, body string, timeout int, follow, insecure bool, cookies, userAgent string) {
	if method == "" {
		method = "GET"
	}
	if timeout <= 0 {
		timeout = 30
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout) * time.Second,
	}
	if !follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		sendToDash(map[string]interface{}{"type": "fetch_response", "id": id, "error": err.Error()})
		return
	}

	ua := userAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	req.Header.Set("User-Agent", ua)

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	if headers != "" {
		for _, h := range strings.Split(headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		sendToDash(map[string]interface{}{"type": "fetch_response", "id": id, "error": err.Error()})
		log.Printf("Fetch error: %v", err)
		return
	}
	defer resp.Body.Close()

	var respHeaders []string
	for k, vals := range resp.Header {
		respHeaders = append(respHeaders, fmt.Sprintf("%s: %s", k, strings.Join(vals, ", ")))
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	sendToDash(map[string]interface{}{
		"type":    "fetch_response",
		"id":      id,
		"status":  resp.StatusCode,
		"headers": strings.Join(respHeaders, "\n"),
		"body":    string(respBody),
	})

	truncURL := rawURL
	if len(truncURL) > 50 {
		truncURL = truncURL[:50]
	}
	log.Printf("%s %s -> %d", method, truncURL, resp.StatusCode)
}

// --- Dashboard WebSocket handler ---

func handleDashboard(conn net.Conn) {
	dashMu.Lock()
	old := dashConn
	dashConn = conn
	dashMu.Unlock()

	if old != nil {
		old.Close()
		log.Println("Previous dashboard disconnected")
	}

	log.Println("Dashboard connected!")

	for {
		data, opcode, err := wsReadFrame(conn)
		if err != nil || opcode == 8 {
			break
		}
		if data == nil {
			continue
		}

		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		msgType, _ := msg["type"].(string)
		sid, _ := msg["session"].(string)
		if sid == "" {
			sid, _ = msg["sid"].(string)
		}

		switch msgType {
		case "connect":
			host, _ := msg["host"].(string)
			port, _ := msg["port"].(float64)
			go handleTCPConnect(sid, host, int(port))

		case "data":
			d, _ := msg["data"].(string)
			handleTCPData(sid, d)

		case "close":
			handleTCPClose(sid)

		case "fetch_request":
			id, _ := msg["id"].(string)
			u, _ := msg["url"].(string)
			m, _ := msg["method"].(string)
			h, _ := msg["headers"].(string)
			b, _ := msg["body"].(string)
			t := 30
			if tv, ok := msg["timeout"].(float64); ok {
				t = int(tv)
			}
			fol := true
			if fv, ok := msg["follow"].(bool); ok {
				fol = fv
			}
			ins := true
			if iv, ok := msg["insecure"].(bool); ok {
				ins = iv
			}
			c, _ := msg["cookies"].(string)
			ua, _ := msg["userAgent"].(string)
			go handleFetch(id, u, m, h, b, t, fol, ins, c, ua)
		}
	}

	dashMu.Lock()
	if dashConn == conn {
		dashConn = nil
	}
	dashMu.Unlock()

	sessionMu.Lock()
	for sid, s := range sessions {
		s.conn.Close()
		delete(sessions, sid)
	}
	sessionMu.Unlock()

	conn.Close()
	log.Println("Dashboard disconnected")
}

// --- HTTP request handler (static files + WS upgrade) ---

func handleConnection(conn net.Conn) {
	buf := make([]byte, 8192)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := conn.Read(buf)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}

	req := string(buf[:n])
	headers := map[string]string{}
	lines := strings.Split(req, "\r\n")
	for _, l := range lines[1:] {
		if idx := strings.Index(l, ":"); idx > 0 {
			headers[strings.ToLower(strings.TrimSpace(l[:idx]))] = strings.TrimSpace(l[idx+1:])
		}
	}

	if strings.EqualFold(headers["upgrade"], "websocket") {
		key := headers["sec-websocket-key"]
		accept := wsAcceptKey(key)
		resp := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
		conn.Write([]byte(resp))
		handleDashboard(conn)
		return
	}

	if len(lines) > 0 && strings.HasPrefix(lines[0], "GET ") {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			reqPath := parts[1]
			if idx := strings.Index(reqPath, "?"); idx >= 0 {
				reqPath = reqPath[:idx]
			}
			reqPath = strings.TrimLeft(reqPath, "/")
			if reqPath == "" || reqPath == "dashboard" {
				reqPath = "dashboard.html"
			}
			reqPath, _ = url.PathUnescape(reqPath)
			clean := filepath.Base(reqPath)

			if allowedFiles[clean] {
				data, err := os.ReadFile(clean)
				if err != nil {
					resp := fmt.Sprintf("HTTP/1.1 404 Not Found\r\n\r\nFile not found: %s", clean)
					conn.Write([]byte(resp))
				} else {
					ct := "application/octet-stream"
					if strings.HasSuffix(clean, ".html") {
						ct = "text/html"
					} else if strings.HasSuffix(clean, ".py") || strings.HasSuffix(clean, ".ps1") {
						ct = "text/plain"
					}
					resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n\r\n", ct, len(data))
					conn.Write([]byte(resp))
					conn.Write(data)
				}
			} else {
				conn.Write([]byte("HTTP/1.1 404 Not Found\r\n\r\nNot found"))
			}
		}
	} else {
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	}

	conn.Close()
}

func main() {
	addr := "127.0.0.1:9999"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	log.Println("========================================")
	log.Printf("Dashboard: http://%s/", addr)
	log.Printf("WebSocket: ws://%s", addr)
	log.Println("========================================")
	log.Println("Put dashboard.html in same directory")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
