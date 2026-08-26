<#
.SYNOPSIS
    SOCKS5 Bridge via Browser Relay (PowerShell version)
.DESCRIPTION
    Run this on Windows Host alongside the dashboard in browser.
    The dashboard handles Ably connectivity; this script provides the SOCKS5 interface.

    Steps:
    1. Run this script with a room code
    2. Open dashboard in browser (from readthedocs.io)
    3. Enter the same room code and join
    4. Click "Connect" in SOCKS Bridge section
    5. Configure apps to use SOCKS5 127.0.0.1:1080

    The browser connects to this script's WebSocket server.
.PARAMETER Room
    4-character room code (same as dashboard)
.PARAMETER SocksPort
    Local SOCKS5 port (default: 1080)
.PARAMETER BridgePort
    Local WebSocket port for browser connection (default: 9998)
#>
param(
    [string]$Room = "",
    [int]$SocksPort = 1080,
    [int]$BridgePort = 9998
)

$ErrorActionPreference = "Stop"

function Log($msg, $color) {
    if (-not $color) { $color = "Gray" }
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" -ForegroundColor $color
}

function Get-WsAccept($key) {
    $guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    $sha = [System.Security.Cryptography.SHA1]::Create()
    [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key + $guid)))
}

function Send-WsFrame($s, [byte[]]$data) {
    $f = [System.Collections.Generic.List[byte]]::new()
    $f.Add(0x81)  # Text frame
    if ($data.Length -lt 126) {
        $f.Add([byte]$data.Length)
    }
    elseif ($data.Length -lt 65536) {
        $f.Add(126)
        $f.Add([byte](($data.Length -shr 8) -band 0xFF))
        $f.Add([byte]($data.Length -band 0xFF))
    }
    else {
        $f.Add(127)
        for ($i = 7; $i -ge 0; $i--) {
            $f.Add([byte](($data.Length -shr ($i*8)) -band 0xFF))
        }
    }
    $f.AddRange($data)
    try { $s.Write($f.ToArray(), 0, $f.Count) } catch { }
}

function Read-WsFrame($s, $timeoutMs = 100) {
    $h = New-Object byte[] 2
    $t = $s.ReadAsync($h, 0, 2)
    if (-not $t.Wait($timeoutMs)) { return $null }
    $n = $t.Result
    if ($n -lt 2) { return $null }

    $op = $h[0] -band 0x0F
    if ($op -eq 8) { return @{op=8; data=$null} }  # Close frame

    $masked = ($h[1] -band 0x80) -ne 0
    $len = $h[1] -band 0x7F

    if ($len -eq 126) {
        $e = New-Object byte[] 2
        $s.Read($e, 0, 2) | Out-Null
        $len = ([int]$e[0] -shl 8) -bor [int]$e[1]
    }
    elseif ($len -eq 127) {
        $e = New-Object byte[] 8
        $s.Read($e, 0, 8) | Out-Null
        $len = 0
        for ($i = 0; $i -lt 8; $i++) { $len = ($len -shl 8) -bor [int]$e[$i] }
    }

    $mask = $null
    if ($masked) {
        $mask = New-Object byte[] 4
        $s.Read($mask, 0, 4) | Out-Null
    }

    if ($len -eq 0) { return @{op=$op; data=[byte[]]@()} }

    $payload = New-Object byte[] $len
    $total = 0
    while ($total -lt $len) {
        $r = $s.Read($payload, $total, $len - $total)
        if ($r -le 0) { break }
        $total += $r
    }

    if ($masked) {
        for ($i = 0; $i -lt $payload.Length; $i++) {
            $payload[$i] = $payload[$i] -bxor $mask[$i % 4]
        }
    }

    @{op=$op; data=$payload}
}

# Session management
$script:sessions = @{}
$script:connectWait = @{}
$script:browserStream = $null
$script:ready = $false

function Send-ToBrowser($msg) {
    if ($script:browserStream) {
        $json = $msg | ConvertTo-Json -Compress -Depth 10
        $data = [System.Text.Encoding]::UTF8.GetBytes($json)
        Send-WsFrame $script:browserStream $data
    }
}

Write-Host ""
Write-Host "=== SOCKS5 Bridge (PowerShell Browser Mode) ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "This bridge connects through your browser." -ForegroundColor White
Write-Host ""

if (-not $Room) {
    Write-Host "Enter room code: " -NoNewline -ForegroundColor Yellow
    $Room = Read-Host
}
$Room = $Room.ToUpper().Trim()

if ($Room.Length -lt 4) {
    Log "ERROR: Room code must be at least 4 characters" Red
    exit 1
}

Write-Host ""
Log "Room: $Room" Cyan
Write-Host ""

# Start WebSocket server for browser
$wsListener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $BridgePort)
$wsListener.Start()
Log "Bridge server: ws://127.0.0.1:$BridgePort" Green
Write-Host ""
Log "Waiting for browser connection..." Yellow
Log "In your browser, open the dashboard and enter room code: $Room" White
Log "Then click 'Connect' in the SOCKS Bridge section." White
Write-Host ""

# Accept browser connection
$browserClient = $null
$timeout = 120

while (-not $browserClient -and $timeout -gt 0) {
    if ($wsListener.Pending()) {
        $browserClient = $wsListener.AcceptTcpClient()
    }
    else {
        Start-Sleep -Milliseconds 500
        $timeout -= 0.5
    }
}

if (-not $browserClient) {
    Log "ERROR: Timeout waiting for browser" Red
    exit 1
}

# WebSocket handshake
$script:browserStream = $browserClient.GetStream()
$reader = New-Object System.IO.StreamReader($script:browserStream)

$reqLine = $reader.ReadLine()
$headers = @{}
while (($line = $reader.ReadLine()) -and $line -ne "") {
    if ($line -match "^([^:]+):\s*(.*)$") {
        $headers[$Matches[1]] = $Matches[2]
    }
}

if (-not $headers["Upgrade"] -or $headers["Upgrade"] -ine "websocket") {
    Log "ERROR: Not a WebSocket request" Red
    $browserClient.Close()
    exit 1
}

$accept = Get-WsAccept $headers["Sec-WebSocket-Key"]
$resp = "HTTP/1.1 101 Switching Protocols`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Accept: $accept`r`n`r`n"
$respBytes = [System.Text.Encoding]::ASCII.GetBytes($resp)
$script:browserStream.Write($respBytes, 0, $respBytes.Length)

Log "Browser connected!" Green

# Send room code to browser
Send-ToBrowser @{
    type = "bridge_init"
    room = $Room
}

$script:ready = $true

# Start SOCKS5 listener
$socksLn = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $SocksPort)
$socksLn.Start()

Write-Host ""
Log "SOCKS5 proxy running on 0.0.0.0:$SocksPort" Green
Write-Host ""
Log "Configure apps to use: SOCKS5 <this-ip>:$SocksPort" Cyan
Write-Host ""

function Process-BrowserMessages {
    while ($browserClient.Available -gt 0) {
        $frame = Read-WsFrame $script:browserStream 50
        if ($null -eq $frame -or $null -eq $frame.data) { continue }
        if ($frame.op -eq 8) {
            Log "Browser disconnected" Yellow
            return $false
        }

        try {
            $json = [System.Text.Encoding]::UTF8.GetString($frame.data)
            $msg = $json | ConvertFrom-Json

            switch ($msg.type) {
                "tcp_connected" {
                    $sid = $msg.session
                    Log "TCP connected: $sid" Green
                    if ($script:connectWait.ContainsKey($sid)) {
                        $script:connectWait[$sid] = "ok"
                    }
                }
                "tcp_data" {
                    $sid = $msg.session
                    if ($script:sessions.ContainsKey($sid)) {
                        $bytes = [Convert]::FromBase64String($msg.data)
                        try {
                            $script:sessions[$sid].GetStream().Write($bytes, 0, $bytes.Length)
                        } catch { }
                    }
                }
                "tcp_closed" {
                    $sid = $msg.session
                    Log "TCP closed: $sid"
                    if ($script:sessions.ContainsKey($sid)) {
                        try { $script:sessions[$sid].Close() } catch { }
                        $script:sessions.Remove($sid)
                    }
                }
                "tcp_error" {
                    $sid = $msg.session
                    $err = $msg.error
                    Log "TCP error [$sid]: $err" Red
                    if ($script:connectWait.ContainsKey($sid)) {
                        $script:connectWait[$sid] = "error"
                    }
                    if ($script:sessions.ContainsKey($sid)) {
                        try { $script:sessions[$sid].Close() } catch { }
                        $script:sessions.Remove($sid)
                    }
                }
            }
        } catch { }
    }
    return $true
}

try {
    while ($browserClient.Connected) {
        if (-not (Process-BrowserMessages)) { break }

        if (-not $socksLn.Pending()) {
            Start-Sleep -Milliseconds 20
            continue
        }

        $sc = $socksLn.AcceptTcpClient()
        $ss = $sc.GetStream()

        try {
            # SOCKS5 handshake
            $buf = New-Object byte[] 512
            $n = $ss.Read($buf, 0, 512)
            if ($n -lt 2 -or $buf[0] -ne 5) {
                $sc.Close()
                continue
            }
            $ss.Write([byte[]](5,0), 0, 2)

            # Read connect request
            $n = $ss.Read($buf, 0, 512)
            if ($n -lt 7 -or $buf[0] -ne 5 -or $buf[1] -ne 1) {
                $ss.Write([byte[]](5,7,0,1,0,0,0,0,0,0), 0, 10)
                $sc.Close()
                continue
            }

            # Parse address
            $host_ = ""
            $port_ = 0
            switch ($buf[3]) {
                1 {  # IPv4
                    $host_ = "$($buf[4]).$($buf[5]).$($buf[6]).$($buf[7])"
                    $port_ = ([int]$buf[8] -shl 8) -bor $buf[9]
                }
                3 {  # Domain
                    $l = $buf[4]
                    $host_ = [System.Text.Encoding]::ASCII.GetString($buf, 5, $l)
                    $port_ = ([int]$buf[5+$l] -shl 8) -bor $buf[6+$l]
                }
                4 {  # IPv6
                    $ss.Write([byte[]](5,8,0,1,0,0,0,0,0,0), 0, 10)
                    $sc.Close()
                    continue
                }
            }

            # Generate session ID
            $sid = "s" + ([DateTimeOffset]::Now.ToUnixTimeMilliseconds() % 1000000)

            Log "CONNECT ${host_}:${port_}"

            # Register session
            $script:sessions[$sid] = $sc
            $script:connectWait[$sid] = "waiting"

            # Send connect request to browser
            Send-ToBrowser @{
                type = "tcp_connect"
                session = $sid
                host = $host_
                port = $port_
            }

            # Wait for tcp_connected
            $timeout = 150  # 15 seconds
            while ($timeout -gt 0 -and $script:connectWait[$sid] -eq "waiting") {
                Process-BrowserMessages | Out-Null
                Start-Sleep -Milliseconds 100
                $timeout--
            }

            $result = $script:connectWait[$sid]
            $script:connectWait.Remove($sid)

            if ($result -ne "ok") {
                Log "Connection failed or timeout" Red
                $ss.Write([byte[]](5,4,0,1,0,0,0,0,0,0), 0, 10)
                $script:sessions.Remove($sid)
                $sc.Close()
                continue
            }

            # Success
            $ss.Write([byte[]](5,0,0,1,0,0,0,0,0,0), 0, 10)

            # Relay data
            $socksBuf = New-Object byte[] 16384
            $idle = 0

            while ($idle -lt 600 -and $sc.Connected -and $browserClient.Connected) {
                Process-BrowserMessages | Out-Null
                $didWork = $false

                # Check if session closed remotely
                if (-not $script:sessions.ContainsKey($sid)) { break }

                # SOCKS -> Browser
                if ($ss.DataAvailable) {
                    try {
                        $n = $ss.Read($socksBuf, 0, $socksBuf.Length)
                        if ($n -gt 0) {
                            # Chunk to stay under Ably limit
                            $chunkSize = 40000
                            $fullData = New-Object byte[] $n
                            [Array]::Copy($socksBuf, $fullData, $n)

                            for ($i = 0; $i -lt $n; $i += $chunkSize) {
                                $len = [Math]::Min($chunkSize, $n - $i)
                                $chunk = New-Object byte[] $len
                                [Array]::Copy($fullData, $i, $chunk, 0, $len)
                                $b64 = [Convert]::ToBase64String($chunk)

                                Send-ToBrowser @{
                                    type = "tcp_data"
                                    session = $sid
                                    data = $b64
                                }
                            }

                            $didWork = $true
                            $idle = 0
                        }
                    } catch { break }
                }

                if (-not $didWork) {
                    $idle++
                    Start-Sleep -Milliseconds 10
                }
            }

            $sc.Close()
            $script:sessions.Remove($sid)

            Send-ToBrowser @{
                type = "tcp_close"
                session = $sid
            }

            Log "Closed: ${host_}:${port_}"

        } catch {
            Log "Error: $_" Red
            try { $sc.Close() } catch { }
        }
    }
}
finally {
    $socksLn.Stop()
    $wsListener.Stop()
    if ($browserClient) { $browserClient.Close() }
    Log "Done"
}
