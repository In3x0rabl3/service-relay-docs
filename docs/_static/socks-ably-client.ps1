<#
.SYNOPSIS
    SOCKS5 proxy via Ably relay - for highly restricted environments.
.DESCRIPTION
    Run this on the restricted Windows Host. Configure apps to use SOCKS5 127.0.0.1:1080.
    Tunnels SOCKS requests through Ably messaging to reach the Ubuntu backend.

    Prerequisites:
    1. Ubuntu-side dashboard must be running and connected to a room
    2. Run this script with the same room code
.PARAMETER Room
    4-character room code (same as dashboard)
.PARAMETER SocksPort
    Local SOCKS5 port (default: 1080)
.PARAMETER AblyKey
    Ably API key (default: embedded key)
#>
param(
    [Parameter(Mandatory=$true)]
    [string]$Room,
    [int]$SocksPort = 1080,
    [string]$AblyKey = "gAgqHA.yZ5GzA:6o4_ysot75A7YNoDEicN23KmBcI3isDJL3uYIUp3Ibg"
)

$ErrorActionPreference = "Stop"

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" }

# Message queue for async handling
$script:incomingQueue = [System.Collections.Concurrent.ConcurrentQueue[hashtable]]::new()
$script:sessions = @{}
$script:sessionConnected = @{}
$script:myId = "ps_" + [guid]::NewGuid().ToString().Substring(0, 8)

function Send-AblyMessage($ws, $msg, $cts) {
    $json = $msg | ConvertTo-Json -Compress -Depth 10
    $data = [System.Text.Encoding]::UTF8.GetBytes($json)
    $seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$data)
    $ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).GetAwaiter().GetResult() | Out-Null
}

function Publish-ToChannel($ws, $channel, $data, $cts) {
    $msg = @{
        action = 15  # MESSAGE
        channel = $channel
        messages = @(@{
            name = "data"
            data = $data
        })
    }
    Send-AblyMessage $ws $msg $cts
}

Log "=== SOCKS5 Ably Bridge ==="
Log "[*] Room: $Room"
Log "[*] My ID: $script:myId"

# Connect to Ably
$wsUri = "wss://realtime.ably.io/?key=$AblyKey&v=1.2&format=json"
$ws = New-Object System.Net.WebSockets.ClientWebSocket
$cts = New-Object System.Threading.CancellationTokenSource

Log "[*] Connecting to Ably..."
try {
    $ws.ConnectAsync([Uri]$wsUri, $cts.Token).GetAwaiter().GetResult() | Out-Null
}
catch {
    Log "[-] Failed to connect to Ably: $_"
    exit 1
}
Log "[+] Connected to Ably"

# Subscribe to channel
$channel = "relay:$Room"
$attachMsg = @{
    action = 10  # ATTACH
    channel = $channel
}
Send-AblyMessage $ws $attachMsg $cts
Log "[*] Subscribing to channel: $channel"

# Wait for ATTACHED response
$buf = New-Object byte[] 65536
$seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$buf)
$task = $ws.ReceiveAsync($seg, $cts.Token)
$task.Wait(5000) | Out-Null
$resp = [System.Text.Encoding]::UTF8.GetString($buf, 0, $task.Result.Count)
if (-not $resp.Contains('"action":11')) {  # ATTACHED
    Log "[-] Failed to attach to channel"
    exit 1
}
Log "[+] Attached to channel"

# Start SOCKS listener
$socksLn = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $SocksPort)
$socksLn.Start()
Log "[+] SOCKS5 listening on 127.0.0.1:$SocksPort"
Log ""

# Background job to read Ably messages
$script:wsRunning = $true
$wsReader = {
    param($ws, $cts, $queue, $buf, $seg)
    while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        try {
            $task = $ws.ReceiveAsync($seg, $cts.Token)
            if ($task.Wait(100)) {
                $count = $task.Result.Count
                if ($count -gt 0) {
                    $json = [System.Text.Encoding]::UTF8.GetString($buf, 0, $count)
                    $msg = $json | ConvertFrom-Json
                    if ($msg.action -eq 15 -and $msg.messages) {
                        foreach ($m in $msg.messages) {
                            if ($m.data.type -and $m.data.from -ne $script:myId) {
                                $queue.Enqueue(@{
                                    type = $m.data.type
                                    session = $m.data.session
                                    data = $m.data.data
                                    error = $m.data.error
                                })
                            }
                        }
                    }
                }
            }
        } catch { }
    }
}

# Start reading in background
$readerJob = Start-Job -ScriptBlock {
    param($wsUri, $AblyKey, $channel, $myId)

    $ws = New-Object System.Net.WebSockets.ClientWebSocket
    $cts = New-Object System.Threading.CancellationTokenSource
    $ws.ConnectAsync([Uri]$wsUri, $cts.Token).GetAwaiter().GetResult() | Out-Null

    $attachMsg = @{ action = 10; channel = $channel } | ConvertTo-Json -Compress
    $data = [System.Text.Encoding]::UTF8.GetBytes($attachMsg)
    $seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$data)
    $ws.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $cts.Token).GetAwaiter().GetResult() | Out-Null
    Start-Sleep -Seconds 1

    $buf = New-Object byte[] 65536
    $seg = New-Object System.ArraySegment[byte] -ArgumentList @(,$buf)

    while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        try {
            $task = $ws.ReceiveAsync($seg, $cts.Token)
            if ($task.Wait(1000)) {
                $count = $task.Result.Count
                if ($count -gt 0) {
                    $json = [System.Text.Encoding]::UTF8.GetString($buf, 0, $count)
                    Write-Output $json
                }
            }
        } catch { }
    }
} -ArgumentList $wsUri, $AblyKey, $channel, $script:myId

function Process-IncomingMessages {
    if ($readerJob.HasMoreData) {
        $outputs = Receive-Job $readerJob
        foreach ($json in $outputs) {
            try {
                $msg = $json | ConvertFrom-Json
                if ($msg.action -eq 15 -and $msg.messages) {
                    foreach ($m in $msg.messages) {
                        $d = $m.data
                        if ($d.from -eq $script:myId) { continue }

                        switch ($d.type) {
                            "tcp_connected" {
                                $sid = $d.session
                                if ($script:sessionConnected.ContainsKey($sid)) {
                                    $script:sessionConnected[$sid] = $true
                                }
                            }
                            "tcp_data" {
                                $sid = $d.session
                                if ($script:sessions.ContainsKey($sid)) {
                                    $bytes = [Convert]::FromBase64String($d.data)
                                    $script:sessions[$sid].GetStream().Write($bytes, 0, $bytes.Length)
                                }
                            }
                            "tcp_closed" {
                                $sid = $d.session
                                if ($script:sessions.ContainsKey($sid)) {
                                    $script:sessions[$sid].Close()
                                    $script:sessions.Remove($sid)
                                }
                            }
                            "tcp_error" {
                                $sid = $d.session
                                Log "[-] TCP error [$sid]: $($d.error)"
                                if ($script:sessionConnected.ContainsKey($sid)) {
                                    $script:sessionConnected[$sid] = "error"
                                }
                            }
                        }
                    }
                }
            } catch { }
        }
    }
}

try {
    while ($ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
        Process-IncomingMessages

        if (-not $socksLn.Pending()) {
            Start-Sleep -Milliseconds 20
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
            $ss.Write([byte[]](5,0), 0, 2)

            # Read connect request
            $n = $ss.Read($buf, 0, 256)
            if ($n -lt 7 -or $buf[0] -ne 5 -or $buf[1] -ne 1) {
                $ss.Write([byte[]](5,7,0,1,0,0,0,0,0,0), 0, 10)
                $sc.Close()
                continue
            }

            # Parse address
            $host_ = ""
            $port_ = 0
            switch ($buf[3]) {
                1 {
                    $host_ = "$($buf[4]).$($buf[5]).$($buf[6]).$($buf[7])"
                    $port_ = ([int]$buf[8] -shl 8) -bor $buf[9]
                }
                3 {
                    $l = $buf[4]
                    $host_ = [System.Text.Encoding]::ASCII.GetString($buf, 5, $l)
                    $port_ = ([int]$buf[5+$l] -shl 8) -bor $buf[6+$l]
                }
                4 {
                    $ss.Write([byte[]](5,8,0,1,0,0,0,0,0,0), 0, 10)
                    $sc.Close()
                    continue
                }
            }

            $sid = "s" + [DateTimeOffset]::Now.ToUnixTimeMilliseconds() % 1000000
            Log "[*] CONNECT ${host_}:${port_} [$sid]"

            # Register session
            $script:sessions[$sid] = $sc
            $script:sessionConnected[$sid] = $false

            # Send tcp_connect to peer via Ably
            Publish-ToChannel $ws $channel @{
                type = "tcp_connect"
                from = $script:myId
                session = $sid
                host = $host_
                port = $port_
            } $cts

            # Wait for tcp_connected
            $timeout = 150  # 15 seconds
            while ($timeout -gt 0 -and $script:sessionConnected[$sid] -eq $false) {
                Process-IncomingMessages
                Start-Sleep -Milliseconds 100
                $timeout--
            }

            if ($script:sessionConnected[$sid] -ne $true) {
                Log "[-] Connection failed or timeout"
                $ss.Write([byte[]](5,4,0,1,0,0,0,0,0,0), 0, 10)
                $script:sessions.Remove($sid)
                $script:sessionConnected.Remove($sid)
                $sc.Close()
                continue
            }

            # Success
            $ss.Write([byte[]](5,0,0,1,0,0,0,0,0,0), 0, 10)
            Log "[+] Tunnel open: ${host_}:${port_}"

            # Relay data
            $socksBuf = New-Object byte[] 8192
            $idle = 0

            while ($idle -lt 500 -and $sc.Connected -and $ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                Process-IncomingMessages
                $didWork = $false

                # Check if session was closed remotely
                if (-not $script:sessions.ContainsKey($sid)) { break }

                # SOCKS -> Ably
                if ($ss.DataAvailable) {
                    try {
                        $n = $ss.Read($socksBuf, 0, $socksBuf.Length)
                        if ($n -gt 0) {
                            # Chunk if needed (Ably 64KB limit)
                            $chunkSize = 40000
                            for ($i = 0; $i -lt $n; $i += $chunkSize) {
                                $len = [Math]::Min($chunkSize, $n - $i)
                                $chunk = New-Object byte[] $len
                                [Array]::Copy($socksBuf, $i, $chunk, 0, $len)
                                $b64 = [Convert]::ToBase64String($chunk)

                                Publish-ToChannel $ws $channel @{
                                    type = "tcp_data"
                                    from = $script:myId
                                    session = $sid
                                    data = $b64
                                } $cts
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
            $script:sessionConnected.Remove($sid)

            Publish-ToChannel $ws $channel @{
                type = "tcp_close"
                from = $script:myId
                session = $sid
            } $cts

            Log "[+] Closed: ${host_}:${port_}"

        } catch {
            Log "[-] Error: $_"
            try { $sc.Close() } catch {}
        }
    }
}
finally {
    $socksLn.Stop()
    $ws.Dispose()
    Stop-Job $readerJob -ErrorAction SilentlyContinue
    Remove-Job $readerJob -ErrorAction SilentlyContinue
    Log "[*] Done"
}
