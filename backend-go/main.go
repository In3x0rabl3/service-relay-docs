package main

import (
	"bufio"
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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
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

// SSPI proxy auth (Windows secur32.dll)
const (
	_SECPKG_CRED_OUTBOUND  = 2
	_SECBUFFER_TOKEN       = 2
	_SECBUFFER_VERSION     = 0
	_SEC_E_OK              = 0
	_SEC_I_CONTINUE_NEEDED = 0x00090312
	_ISC_REQ_CONNECTION    = 0x00000800
	_SECURITY_NATIVE_DREP  = 0x10
)

type sspiHandle struct {
	lower uintptr
	upper uintptr
}

type sspiBuffer struct {
	size       uint32
	bufferType uint32
	data       uintptr
}

type sspiBufferDesc struct {
	version uint32
	count   uint32
	buffers uintptr
}

var (
	secur32DLL      = syscall.NewLazyDLL("secur32.dll")
	sspiAcquireFn   = secur32DLL.NewProc("AcquireCredentialsHandleW")
	sspiInitFn      = secur32DLL.NewProc("InitializeSecurityContextW")
	sspiDeleteCtxFn = secur32DLL.NewProc("DeleteSecurityContext")
	sspiFreeCredFn  = secur32DLL.NewProc("FreeCredentialsHandle")
)

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

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

// --- System proxy detection ---

var systemProxy string

func regValue(key, name string) string {
	out, err := exec.Command("reg", "query", key, "/v", name).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, name) {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				return parts[len(parts)-1]
			}
		}
	}
	return ""
}

func parseProxyString(proxy string) string {
	if strings.Contains(proxy, "=") {
		for _, p := range strings.Split(proxy, ";") {
			kv := strings.SplitN(p, "=", 2)
			if len(kv) == 2 && (kv[0] == "https" || kv[0] == "http") {
				proxy = kv[1]
				break
			}
		}
	}
	if proxy != "" && !strings.HasPrefix(proxy, "http") {
		proxy = "http://" + proxy
	}
	return proxy
}

func proxyFromPAC(pacURL string) string {
	log.Printf("PAC URL: %s", pacURL)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(pacURL)
	if err != nil {
		log.Printf("PAC download failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	pac := string(body)
	log.Printf("PAC file: %d bytes", len(pac))
	upper := strings.ToUpper(pac)
	idx := 0
	for {
		pos := strings.Index(upper[idx:], "PROXY ")
		if pos < 0 {
			break
		}
		pos += idx + 6
		rest := strings.TrimSpace(pac[pos:])
		end := strings.IndexAny(rest, `"';, `)
		if end > 0 {
			rest = rest[:end]
		}
		rest = strings.TrimSpace(rest)
		if rest != "" && strings.Contains(rest, ":") && !strings.EqualFold(rest, "DIRECT") {
			p := "http://" + rest
			log.Printf("PAC proxy found: %s", p)
			return p
		}
		idx = pos
	}
	log.Println("PAC: no PROXY directive found")
	return ""
}

func detectProxy() string {
	const regKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	for _, v := range []string{"HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"} {
		if p := os.Getenv(v); p != "" {
			log.Printf("Proxy [env %s]: %s", v, p)
			return p
		}
	}

	if regValue(regKey, "ProxyEnable") == "0x1" {
		if srv := regValue(regKey, "ProxyServer"); srv != "" {
			p := parseProxyString(srv)
			log.Printf("Proxy [registry]: %s", p)
			return p
		}
	}

	if pacURL := regValue(regKey, "AutoConfigURL"); pacURL != "" {
		if p := proxyFromPAC(pacURL); p != "" {
			return p
		}
	}

	if p := proxyFromPAC("http://wpad/wpad.dat"); p != "" {
		log.Println("Proxy [WPAD]")
		return p
	}

	return ""
}

func proxyTransport(insecure bool) *http.Transport {
	t := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	if systemProxy != "" {
		t.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port := 443
			fmt.Sscanf(portStr, "%d", &port)
			return connectViaProxy(host, port)
		}
	}
	return t
}

func connectViaProxy(host string, port int) (net.Conn, error) {
	u, err := url.Parse(systemProxy)
	if err != nil {
		return nil, err
	}
	proxyAddr := u.Host
	if _, _, e := net.SplitHostPort(proxyAddr); e != nil {
		proxyAddr += ":8080"
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("proxy connect: %v", err)
	}

	target := fmt.Sprintf("%s:%d", host, port)
	br := bufio.NewReader(conn)
	connectReq := &http.Request{Method: "CONNECT"}

	// Try unauthenticated CONNECT first
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n", target, target)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy response: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode == 200 {
		log.Printf("TCP [proxy CONNECT] -> %s", target)
		return &bufferedConn{Conn: conn, r: br}, nil
	}

	if resp.StatusCode != 407 {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT: %d %s", resp.StatusCode, resp.Status)
	}

	// 407 — pick Negotiate or NTLM
	scheme := ""
	for _, v := range resp.Header.Values("Proxy-Authenticate") {
		if strings.HasPrefix(strings.TrimSpace(v), "Negotiate") {
			scheme = "Negotiate"
			break
		}
	}
	if scheme == "" {
		for _, v := range resp.Header.Values("Proxy-Authenticate") {
			if strings.HasPrefix(strings.TrimSpace(v), "NTLM") {
				scheme = "NTLM"
				break
			}
		}
	}
	if scheme == "" {
		conn.Close()
		return nil, fmt.Errorf("proxy 407: no Negotiate/NTLM in %v", resp.Header.Values("Proxy-Authenticate"))
	}
	log.Printf("Proxy auth scheme: %s", scheme)

	// Always reconnect — many proxies close after the initial 407 without
	// sending Connection: close, causing "forcibly closed" on the next write.
	conn.Close()
	conn, err = net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("proxy reconnect: %v", err)
	}
	br = bufio.NewReader(conn)

	// SSPI: acquire current user's credentials
	pkgName, _ := syscall.UTF16PtrFromString(scheme)
	var credHandle sspiHandle
	var credExpiry int64
	ret, _, _ := sspiAcquireFn.Call(
		0,
		uintptr(unsafe.Pointer(pkgName)),
		_SECPKG_CRED_OUTBOUND,
		0, 0, 0, 0,
		uintptr(unsafe.Pointer(&credHandle)),
		uintptr(unsafe.Pointer(&credExpiry)),
	)
	if ret != _SEC_E_OK {
		conn.Close()
		return nil, fmt.Errorf("SSPI AcquireCredentials: 0x%x", ret)
	}
	defer sspiFreeCredFn.Call(uintptr(unsafe.Pointer(&credHandle)))

	proxyHost := u.Hostname()
	targetSPN, _ := syscall.UTF16PtrFromString("HTTP/" + proxyHost)
	var ctxHandle sspiHandle
	haveCtx := false
	challenge := ""

	for round := 0; round < 3; round++ {
		outBuf := make([]byte, 12288)
		outSecBuf := sspiBuffer{
			size:       uint32(len(outBuf)),
			bufferType: _SECBUFFER_TOKEN,
			data:       uintptr(unsafe.Pointer(&outBuf[0])),
		}
		outDesc := sspiBufferDesc{
			version: _SECBUFFER_VERSION,
			count:   1,
			buffers: uintptr(unsafe.Pointer(&outSecBuf)),
		}

		var inDesc sspiBufferDesc
		var inSecBuf sspiBuffer
		var challengeBytes []byte
		var inDescArg uintptr

		if challenge != "" {
			challengeBytes, err = base64.StdEncoding.DecodeString(challenge)
			if err != nil {
				if haveCtx {
					sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
				}
				conn.Close()
				return nil, fmt.Errorf("SSPI decode challenge: %v", err)
			}
			inSecBuf = sspiBuffer{
				size:       uint32(len(challengeBytes)),
				bufferType: _SECBUFFER_TOKEN,
				data:       uintptr(unsafe.Pointer(&challengeBytes[0])),
			}
			inDesc = sspiBufferDesc{
				version: _SECBUFFER_VERSION,
				count:   1,
				buffers: uintptr(unsafe.Pointer(&inSecBuf)),
			}
			inDescArg = uintptr(unsafe.Pointer(&inDesc))
		}

		var ctxIn uintptr
		if haveCtx {
			ctxIn = uintptr(unsafe.Pointer(&ctxHandle))
		}

		var contextAttr uint32
		var contextExpiry int64

		ret, _, _ = sspiInitFn.Call(
			uintptr(unsafe.Pointer(&credHandle)),
			ctxIn,
			uintptr(unsafe.Pointer(targetSPN)),
			_ISC_REQ_CONNECTION,
			0,
			_SECURITY_NATIVE_DREP,
			inDescArg,
			0,
			uintptr(unsafe.Pointer(&ctxHandle)),
			uintptr(unsafe.Pointer(&outDesc)),
			uintptr(unsafe.Pointer(&contextAttr)),
			uintptr(unsafe.Pointer(&contextExpiry)),
		)
		runtime.KeepAlive(challengeBytes)
		runtime.KeepAlive(&inSecBuf)
		runtime.KeepAlive(&inDesc)
		runtime.KeepAlive(outBuf)
		runtime.KeepAlive(&outSecBuf)

		haveCtx = true

		if ret != _SEC_E_OK && ret != _SEC_I_CONTINUE_NEEDED {
			sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
			conn.Close()
			return nil, fmt.Errorf("SSPI InitSecurityContext: 0x%x", ret)
		}

		token := base64.StdEncoding.EncodeToString(outBuf[:outSecBuf.size])
		log.Printf("SSPI round %d: %d bytes token", round+1, outSecBuf.size)

		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s %s\r\nProxy-Connection: keep-alive\r\n\r\n",
			target, target, scheme, token)

		resp, err = http.ReadResponse(br, connectReq)
		if err != nil {
			sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
			conn.Close()
			return nil, fmt.Errorf("proxy auth response: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == 200 {
			sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
			log.Printf("TCP [proxy CONNECT+SSPI %s] -> %s", scheme, target)
			return &bufferedConn{Conn: conn, r: br}, nil
		}

		if resp.StatusCode != 407 {
			sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
			conn.Close()
			return nil, fmt.Errorf("proxy auth failed: %d %s", resp.StatusCode, resp.Status)
		}

		if ret != _SEC_I_CONTINUE_NEEDED {
			sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
			conn.Close()
			return nil, fmt.Errorf("proxy 407 but SSPI done (no continue)")
		}

		// Extract challenge token for next round
		challenge = ""
		for _, v := range resp.Header.Values("Proxy-Authenticate") {
			v = strings.TrimSpace(v)
			if strings.HasPrefix(v, scheme+" ") {
				challenge = strings.TrimSpace(strings.TrimPrefix(v, scheme+" "))
				break
			}
		}
		if challenge == "" {
			sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
			conn.Close()
			return nil, fmt.Errorf("proxy 407 round %d: no challenge token", round+1)
		}
	}

	if haveCtx {
		sspiDeleteCtxFn.Call(uintptr(unsafe.Pointer(&ctxHandle)))
	}
	conn.Close()
	return nil, fmt.Errorf("proxy SSPI: too many auth rounds")
}

func dialTCP(host string, port int) (net.Conn, error) {
	if systemProxy != "" {
		return connectViaProxy(host, port)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, _ := net.DefaultResolver.LookupHost(ctx, host)
	if len(ips) > 0 {
		host = ips[0]
	}
	return net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
}

// --- TCP tunnel ---

func handleTCPConnect(session, host string, port int) {
	conn, err := dialTCP(host, port)
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
	log.Printf("TCP [%s] -> %s:%d", session, host, port)

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

	client := &http.Client{
		Transport: proxyTransport(insecure),
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

	systemProxy = detectProxy()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}

	log.Println("========================================")
	log.Printf("Dashboard: http://%s/", addr)
	log.Printf("WebSocket: ws://%s", addr)
	if systemProxy != "" {
		log.Printf("Proxy: %s", systemProxy)
	} else {
		log.Println("Proxy: none (direct)")
	}
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
