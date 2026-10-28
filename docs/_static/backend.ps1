<#
.SYNOPSIS
    WebSocket backend for TCP proxying and HTTP fetching (PowerShell version)
.DESCRIPTION
    Provides the exit-node backend for the service relay dashboard.
    Accepts a WebSocket connection from the dashboard and handles:
    - TCP tunnel sessions (connect/data/close)
    - HTTP fetch requests (curl-like)
    - Static file serving (dashboard.html, tools)

    Usage: .\backend.ps1 [-Port 9999] [-ListenAddr 127.0.0.1]
.PARAMETER Port
    Listening port (default: 9999)
.PARAMETER ListenAddr
    Bind address (default: 127.0.0.1)
#>
param(
    [int]$Port = 9999,
    [string]$ListenAddr = "127.0.0.1"
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http

function Log($msg, $lvl) {
    $c = switch ($lvl) { "ERR" { "Red" } "WARN" { "Yellow" } "OK" { "Green" } default { "Gray" } }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $c
}

# --- WebSocket framing ---

function Get-WsAccept($key) {
    $sha = [System.Security.Cryptography.SHA1]::Create()
    [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
}

function Send-WsFrame($stream, [byte[]]$data) {
    $f = [System.Collections.Generic.List[byte]]::new()
    $f.Add(0x81)
    if ($data.Length -lt 126) {
        $f.Add([byte]$data.Length)
    } elseif ($data.Length -lt 65536) {
        $f.Add(126)
        $f.Add([byte](($data.Length -shr 8) -band 0xFF))
        $f.Add([byte]($data.Length -band 0xFF))
    } else {
        $f.Add(127)
        for ($i = 7; $i -ge 0; $i--) { $f.Add([byte](($data.Length -shr ($i*8)) -band 0xFF)) }
    }
    $f.AddRange($data)
    try { $stream.Write($f.ToArray(), 0, $f.Count) } catch { }
}

function Send-WsJson($stream, $obj) {
    $json = $obj | ConvertTo-Json -Compress -Depth 10
    Send-WsFrame $stream ([Text.Encoding]::UTF8.GetBytes($json))
}

function Read-WsFrame($stream, $timeoutMs = 50) {
    $h = New-Object byte[] 2
    $t = $stream.ReadAsync($h, 0, 2)
    if (-not $t.Wait($timeoutMs)) { return $null }
    if ($t.Result -lt 2) { return $null }

    $op = $h[0] -band 0x0F
    if ($op -eq 8) { return @{op=8; data=$null} }

    $masked = ($h[1] -band 0x80) -ne 0
    $len = $h[1] -band 0x7F

    if ($len -eq 126) {
        $e = New-Object byte[] 2; $stream.Read($e, 0, 2) | Out-Null
        $len = ([int]$e[0] -shl 8) -bor [int]$e[1]
    } elseif ($len -eq 127) {
        $e = New-Object byte[] 8; $stream.Read($e, 0, 8) | Out-Null
        $len = 0; for ($i = 0; $i -lt 8; $i++) { $len = ($len -shl 8) -bor [int]$e[$i] }
    }

    $mask = $null
    if ($masked) { $mask = New-Object byte[] 4; $stream.Read($mask, 0, 4) | Out-Null }

    $maxFrame = 16 * 1024 * 1024 # 16 MB
    if ($len -gt $maxFrame) { Log "Frame too large: $len bytes" "ERR"; return $null }

    if ($len -eq 0) { return @{op=$op; data=[byte[]]@()} }

    $payload = New-Object byte[] $len
    $total = 0
    while ($total -lt $len) {
        $r = $stream.Read($payload, $total, $len - $total)
        if ($r -le 0) { break }
        $total += $r
    }

    if ($masked) { for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = $payload[$i] -bxor $mask[$i % 4] } }
    @{op=$op; data=$payload}
}

# --- Static file serving ---

$ALLOWED_FILES = @(
    'dashboard.html', 'backend.py', 'backend.ps1', 'backend.txt', 'backend-b64.txt',
    'socks-bridge.txt', 'socks-bridge.ps1', 'socks-bridge.py', 'socks-bridge-b64.txt',
    'port-forward.txt', 'port-forward-b64.txt'
)

function Serve-StaticFile($stream, $path) {
    $clean = [IO.Path]::GetFileName($path)
    if ($clean -notin $ALLOWED_FILES) {
        $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`n`r`nNot found")
        $stream.Write($resp, 0, $resp.Length)
        return
    }
    try {
        $data = [IO.File]::ReadAllBytes($clean)
        $ct = if ($clean.EndsWith('.html')) { 'text/html' }
              elseif ($clean.EndsWith('.py') -or $clean.EndsWith('.ps1')) { 'text/plain' }
              else { 'application/octet-stream' }
        $hdr = "HTTP/1.1 200 OK`r`nContent-Type: $ct`r`nContent-Length: $($data.Length)`r`n`r`n"
        $hdrBytes = [Text.Encoding]::ASCII.GetBytes($hdr)
        $stream.Write($hdrBytes, 0, $hdrBytes.Length)
        $stream.Write($data, 0, $data.Length)
    } catch {
        $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 404 Not Found`r`n`r`nFile not found: $clean")
        $stream.Write($resp, 0, $resp.Length)
    }
}

# --- HTTP fetch ---

function Invoke-Fetch($wsStream, $id, $url, $method, $headers, $body, $timeout, $follow, $insecure, $cookies, $userAgent) {
    try {
        $handler = New-Object System.Net.Http.HttpClientHandler
        if ($insecure) {
            $handler.ServerCertificateCustomValidationCallback = { $true }
        }
        $handler.AllowAutoRedirect = [bool]$follow
        if ($cookies) { $handler.UseCookies = $false }

        $client = New-Object System.Net.Http.HttpClient($handler)
        $client.Timeout = [TimeSpan]::FromSeconds($timeout)

        $ua = if ($userAgent) { $userAgent } else { "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" }
        $client.DefaultRequestHeaders.UserAgent.ParseAdd($ua)

        $req = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($method), $url)

        if ($cookies) { $req.Headers.TryAddWithoutValidation("Cookie", $cookies) | Out-Null }

        if ($headers) {
            foreach ($h in $headers.Split(',')) {
                if ($h -match '^([^:]+):\s*(.*)$') {
                    $req.Headers.TryAddWithoutValidation($Matches[1].Trim(), $Matches[2].Trim()) | Out-Null
                }
            }
        }

        if ($body) {
            $req.Content = New-Object System.Net.Http.StringContent($body, [Text.Encoding]::UTF8, "application/x-www-form-urlencoded")
        }

        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $respHeaders = @()
        foreach ($kv in $resp.Headers) { $respHeaders += "$($kv.Key): $($kv.Value -join ', ')" }
        foreach ($kv in $resp.Content.Headers) { $respHeaders += "$($kv.Key): $($kv.Value -join ', ')" }

        $respBody = $resp.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($respBody.Length -gt 1048576) { $respBody = $respBody.Substring(0, 1048576) }

        Send-WsJson $wsStream @{
            type = "fetch_response"; id = $id; status = [int]$resp.StatusCode
            headers = ($respHeaders -join "`n"); body = $respBody
        }
        Log "$method $($url.Substring(0, [Math]::Min(50, $url.Length))) -> $([int]$resp.StatusCode)"
        $client.Dispose()
    } catch {
        Send-WsJson $wsStream @{ type = "fetch_response"; id = $id; error = $_.Exception.Message }
        Log "Fetch error: $_" "ERR"
    }
}

# --- TCP session management ---

$script:tcpSessions = @{}

function Open-TcpSession($wsStream, $session, $host_, $port_) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.ConnectAsync($host_, $port_).Wait(10000) | Out-Null
        if (-not $tcp.Connected) { throw "Connection timed out" }
        $script:tcpSessions[$session] = @{ tcp = $tcp; stream = $tcp.GetStream() }
        Send-WsJson $wsStream @{ type = "connected"; session = $session }
        Log "TCP [$session] -> ${host_}:${port_}" "OK"
    } catch {
        Send-WsJson $wsStream @{ type = "error"; session = $session; msg = $_.Exception.Message }
        Log "TCP error [$session]: $_" "ERR"
    }
}

function Poll-TcpSessions($wsStream) {
    $toRemove = @()
    foreach ($sid in @($script:tcpSessions.Keys)) {
        $s = $script:tcpSessions[$sid]
        try {
            if (-not $s.tcp.Connected) { $toRemove += $sid; continue }
            $ns = $s.stream
            if ($ns.DataAvailable) {
                $buf = New-Object byte[] 4096
                $n = $ns.Read($buf, 0, $buf.Length)
                if ($n -gt 0) {
                    $chunk = New-Object byte[] $n
                    [Array]::Copy($buf, $chunk, $n)
                    Send-WsJson $wsStream @{
                        type = "data"; session = $sid
                        data = [Convert]::ToBase64String($chunk)
                    }
                } else { $toRemove += $sid }
            }
        } catch { $toRemove += $sid }
    }
    foreach ($sid in $toRemove) {
        try { $script:tcpSessions[$sid].tcp.Close() } catch { }
        $script:tcpSessions.Remove($sid)
        Send-WsJson $wsStream @{ type = "closed"; session = $sid }
        Log "TCP closed: $sid"
    }
}

# --- WebSocket message handler ---

function Handle-WsMessage($wsStream, $data) {
    try {
        $json = [Text.Encoding]::UTF8.GetString($data)
        $msg = $json | ConvertFrom-Json
    } catch { return }

    switch ($msg.type) {
        "connect" {
            $s = if ($msg.session) { $msg.session } else { $msg.sid }
            Open-TcpSession $wsStream $s $msg.host $msg.port
        }
        "data" {
            $s = if ($msg.session) { $msg.session } else { $msg.sid }
            if ($script:tcpSessions.ContainsKey($s)) {
                try {
                    $bytes = [Convert]::FromBase64String($msg.data)
                    $script:tcpSessions[$s].stream.Write($bytes, 0, $bytes.Length)
                } catch { }
            }
        }
        "close" {
            $s = if ($msg.session) { $msg.session } else { $msg.sid }
            if ($script:tcpSessions.ContainsKey($s)) {
                try { $script:tcpSessions[$s].tcp.Close() } catch { }
                $script:tcpSessions.Remove($s)
                Send-WsJson $wsStream @{ type = "closed"; session = $s }
            }
        }
        "fetch_request" {
            $m = $msg
            Invoke-Fetch $wsStream $m.id $m.url `
                $(if ($m.method) { $m.method } else { "GET" }) `
                $(if ($m.headers) { $m.headers } else { "" }) `
                $(if ($m.body) { $m.body } else { "" }) `
                $(if ($m.timeout) { $m.timeout } else { 30 }) `
                $(if ($null -ne $m.follow) { $m.follow } else { $true }) `
                $(if ($null -ne $m.insecure) { $m.insecure } else { $true }) `
                $(if ($m.cookies) { $m.cookies } else { "" }) `
                $(if ($m.userAgent) { $m.userAgent } else { "" })
        }
    }
}

# --- Main ---

Write-Host ""
Write-Host "=== Service Relay Backend (PowerShell) ===" -ForegroundColor Cyan
Write-Host ""

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($ListenAddr), $Port)
$listener.Start()

Log "========================================" "OK"
Log "Dashboard: http://${ListenAddr}:${Port}/" "OK"
Log "WebSocket: ws://${ListenAddr}:${Port}" "OK"
Log "========================================" "OK"
Log "Put dashboard.html in same directory"
Write-Host ""

$dashboardClient = $null
$dashboardStream = $null

try {
    while ($true) {
        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            $cStream = $client.GetStream()

            $buf = New-Object byte[] 8192
            $n = $cStream.Read($buf, 0, $buf.Length)
            $reqStr = [Text.Encoding]::ASCII.GetString($buf, 0, $n)

            $reqHeaders = @{}
            $lines = $reqStr.Split("`r`n")
            foreach ($l in $lines[1..($lines.Length-1)]) {
                if ($l -match '^([^:]+):\s*(.*)$') {
                    $reqHeaders[$Matches[1].ToLower().Trim()] = $Matches[2].Trim()
                }
            }

            if ($reqHeaders["upgrade"] -ieq "websocket") {
                $key = $reqHeaders["sec-websocket-key"]
                $accept = Get-WsAccept $key
                $resp = "HTTP/1.1 101 Switching Protocols`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Accept: $accept`r`n`r`n"
                $respBytes = [Text.Encoding]::ASCII.GetBytes($resp)
                $cStream.Write($respBytes, 0, $respBytes.Length)

                if ($dashboardClient) {
                    try { $dashboardClient.Close() } catch { }
                    Log "Previous dashboard disconnected"
                }
                $dashboardClient = $client
                $dashboardStream = $cStream
                Log "Dashboard connected!" "OK"
                continue
            }

            if ($lines[0] -match '^GET\s+(/[^\s]*)\s') {
                $path = $Matches[1].Split('?')[0].TrimStart('/')
                if (-not $path -or $path -eq 'dashboard') { $path = 'dashboard.html' }
                Serve-StaticFile $cStream $path
            } else {
                $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 400 Bad Request`r`n`r`n")
                $cStream.Write($resp, 0, $resp.Length)
            }
            $client.Close()
            continue
        }

        if ($dashboardClient -and $dashboardClient.Connected -and $dashboardStream) {
            try {
                if ($dashboardClient.Available -gt 0) {
                    $frame = Read-WsFrame $dashboardStream 50
                    if ($frame) {
                        if ($frame.op -eq 8) {
                            Log "Dashboard disconnected" "WARN"
                            $dashboardClient.Close()
                            $dashboardClient = $null
                            $dashboardStream = $null
                        } elseif ($frame.data) {
                            Handle-WsMessage $dashboardStream $frame.data
                        }
                    }
                }
            } catch {
                Log "Dashboard error: $_" "ERR"
                try { $dashboardClient.Close() } catch { }
                $dashboardClient = $null
                $dashboardStream = $null
            }
        }

        if ($dashboardStream) { Poll-TcpSessions $dashboardStream }

        Start-Sleep -Milliseconds 10
    }
} finally {
    foreach ($sid in @($script:tcpSessions.Keys)) {
        try { $script:tcpSessions[$sid].tcp.Close() } catch { }
    }
    if ($dashboardClient) { try { $dashboardClient.Close() } catch { } }
    $listener.Stop()
    Log "Shutdown complete"
}
