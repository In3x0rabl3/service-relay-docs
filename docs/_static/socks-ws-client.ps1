<#
.SYNOPSIS
    SOCKS5 proxy client - listens locally on 1080, forwards over WebSocket.
.DESCRIPTION
    Run this on the restricted Windows Host. Configure apps to use SOCKS5 127.0.0.1:1080.
    Connects to the server via WebSocket and tunnels all SOCKS requests.
.PARAMETER Server
    WebSocket server address (host:port)
.PARAMETER SocksPort
    Local SOCKS5 port (default: 1080)
.PARAMETER UseTLS
    Use secure WebSocket (wss://)
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Server,
    [int]$SocksPort = 1080,
    [switch]$UseTLS
)

$ErrorActionPreference = "Stop"

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" }

function Send-WsText($ws, [string]$text, $cts) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($text)
    $seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$bytes)
    $ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).GetAwaiter().GetResult() | Out-Null
}

function Send-WsBinary($ws, [byte[]]$data, $cts) {
    $seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$data)
    $ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $cts.Token).GetAwaiter().GetResult() | Out-Null
}

$parts = $Server -split ":"
$hostName = $parts[0]
$port = if ($parts.Length -gt 1) { [int]$parts[1] } else { if ($UseTLS) { 443 } else { 8080 } }
$scheme = if ($UseTLS) { "wss" } else { "ws" }
$uri = [Uri]"${scheme}://${hostName}:${port}/"

Log "=== SOCKS5 WebSocket Client ==="
Log "[*] Connecting to $uri..."

$ws = New-Object System.Net.WebSockets.ClientWebSocket
$cts = New-Object System.Threading.CancellationTokenSource

try {
    $ws.ConnectAsync($uri, $cts.Token).GetAwaiter().GetResult() | Out-Null
}
catch {
    Log "[-] Connection failed: $_"
    exit 1
}

Log "[+] Connected to server"

# Start local SOCKS5 listener
$socksLn = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $SocksPort)
$socksLn.Start()
Log "[+] SOCKS5 listening on 127.0.0.1:$SocksPort"
Log "[*] Configure apps to use: SOCKS5 127.0.0.1:$SocksPort"
Log ""

$wsBuf = New-Object byte[] 65536
$wsSeg = New-Object System.ArraySegment[byte] -ArgumentList @(,$wsBuf)

while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
    if (-not $socksLn.Pending()) {
        Start-Sleep -Milliseconds 50
        continue
    }

    $sc = $socksLn.AcceptTcpClient()
    $ss = $sc.GetStream()

    try {
        # SOCKS5 handshake
        $buf = New-Object byte[] 256
        $n = $ss.Read($buf, 0, 256)
        if ($n -lt 3 -or $buf[0] -ne 5) {
            $sc.Close()
            continue
        }
        $ss.Write([byte[]](5,0), 0, 2)  # No auth

        # Read connect request
        $n = $ss.Read($buf, 0, 256)
        if ($n -lt 7 -or $buf[0] -ne 5 -or $buf[1] -ne 1) {
            $ss.Write([byte[]](5,7,0,1,0,0,0,0,0,0), 0, 10)  # Command not supported
            $sc.Close()
            continue
        }

        # Parse address
        $addr = ""
        switch ($buf[3]) {
            1 {  # IPv4
                $addr = "$($buf[4]).$($buf[5]).$($buf[6]).$($buf[7]):$(([int]$buf[8] -shl 8) -bor $buf[9])"
            }
            3 {  # Domain
                $l = $buf[4]
                $addr = [System.Text.Encoding]::ASCII.GetString($buf, 5, $l) + ":$(([int]$buf[5+$l] -shl 8) -bor $buf[6+$l])"
            }
            4 {  # IPv6 not supported
                $ss.Write([byte[]](5,8,0,1,0,0,0,0,0,0), 0, 10)
                $sc.Close()
                continue
            }
        }

        Log "[*] CONNECT $addr"

        # Send connect request to server
        Send-WsText $ws "CONNECT:$addr" $cts

        # Wait for response
        $wsTask = $ws.ReceiveAsync($wsSeg, $cts.Token)
        if (-not $wsTask.Wait(15000)) {
            Log "[-] Timeout waiting for server"
            $ss.Write([byte[]](5,4,0,1,0,0,0,0,0,0), 0, 10)  # Host unreachable
            $sc.Close()
            continue
        }

        $res = $wsTask.GetAwaiter().GetResult()
        $resp = [System.Text.Encoding]::UTF8.GetString($wsBuf, 0, $res.Count)

        if ($resp -ne "OK") {
            Log "[-] Server rejected: $resp"
            $ss.Write([byte[]](5,5,0,1,0,0,0,0,0,0), 0, 10)  # Connection refused
            $sc.Close()
            continue
        }

        # Success - tell SOCKS client
        $ss.Write([byte[]](5,0,0,1,0,0,0,0,0,0), 0, 10)
        Log "[+] Tunnel open: $addr"

        # Relay data bidirectionally
        $socksBuf = New-Object byte[] 8192
        $pendingWsTask = $null
        $idle = 0

        while ($idle -lt 300 -and $sc.Connected -and $ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $didWork = $false

            # SOCKS -> WebSocket
            if ($ss.DataAvailable) {
                try {
                    $n = $ss.Read($socksBuf, 0, $socksBuf.Length)
                    if ($n -gt 0) {
                        $chunk = New-Object byte[] $n
                        [Array]::Copy($socksBuf, $chunk, $n)
                        Send-WsBinary $ws $chunk $cts
                        $didWork = $true
                        $idle = 0
                    }
                } catch { break }
            }

            # WebSocket -> SOCKS
            if ($null -eq $pendingWsTask) {
                $pendingWsTask = $ws.ReceiveAsync($wsSeg, $cts.Token)
            }
            if ($pendingWsTask.Wait(10)) {
                try {
                    $wsRes = $pendingWsTask.GetAwaiter().GetResult()
                    $pendingWsTask = $null

                    if ($wsRes.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Binary -and $wsRes.Count -gt 0) {
                        $ss.Write($wsBuf, 0, $wsRes.Count)
                        $didWork = $true
                        $idle = 0
                    }
                    elseif ($wsRes.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Text) {
                        $cmd = [System.Text.Encoding]::UTF8.GetString($wsBuf, 0, $wsRes.Count)
                        if ($cmd -eq "CLOSE") { break }
                    }
                    elseif ($wsRes.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                        break
                    }
                } catch { break }
            }

            if (-not $didWork) {
                $idle++
                Start-Sleep -Milliseconds 10
            }
        }

        $sc.Close()
        Send-WsText $ws "CLOSE" $cts
        Log "[+] Closed: $addr"

    } catch {
        Log "[-] Error: $_"
        try { $sc.Close() } catch {}
    }
}

$socksLn.Stop()
$ws.Dispose()
Log "[*] Done"
