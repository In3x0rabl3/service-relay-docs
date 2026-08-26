<#
.SYNOPSIS
    SOCKS5 WebSocket server - accepts client connections and makes actual TCP connections.
.DESCRIPTION
    Run this on the target machine that has unrestricted internet access.
    Accepts WebSocket connections from socks-ws-client.ps1 and proxies TCP traffic.
.PARAMETER Port
    WebSocket listen port (default: 8080)
.PARAMETER BindAddress
    Address to bind to (default: 0.0.0.0 for all interfaces)
#>
param(
    [int]$Port = 8080,
    [string]$BindAddress = "0.0.0.0"
)

$ErrorActionPreference = "Stop"

function Log($msg) { Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg" }

function Get-WsAccept($key) {
    $guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    $sha = [System.Security.Cryptography.SHA1]::Create()
    [Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key + $guid)))
}

function Send-WsFrame($s, [byte]$op, [byte[]]$data) {
    $f = [System.Collections.Generic.List[byte]]::new()
    $f.Add(0x80 -bor $op)  # FIN + opcode
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
    $s.Write($f.ToArray(), 0, $f.Count)
}

function Send-WsText($s, [string]$text) {
    Send-WsFrame $s 1 ([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Send-WsBinary($s, [byte[]]$data) {
    Send-WsFrame $s 2 $data
}

function Read-WsFrame($s, $timeoutMs = 30000) {
    $h = New-Object byte[] 2
    $t = $s.ReadAsync($h, 0, 2)
    if (-not $t.Wait($timeoutMs)) { return @{op=0; data=$null} }
    $n = $t.Result
    if ($n -lt 2) { return @{op=0; data=$null} }

    $op = $h[0] -band 0x0F
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

$bindIP = [System.Net.IPAddress]::Parse($BindAddress)
$listener = [System.Net.Sockets.TcpListener]::new($bindIP, $Port)
$listener.Start()

Log "=== SOCKS5 WebSocket Server ==="
Log "[+] Listening on ${BindAddress}:${Port}"
Log "[*] Run client: .\socks-ws-client.ps1 -Server <this-ip>:$Port"
Log ""

while ($true) {
    $client = $listener.AcceptTcpClient()
    $clientIP = $client.Client.RemoteEndPoint.ToString()
    Log "[+] Connection from $clientIP"

    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream)

    # Read HTTP request
    $reqLine = $reader.ReadLine()
    $headers = @{}
    while (($line = $reader.ReadLine()) -and $line -ne "") {
        if ($line -match "^([^:]+):\s*(.*)$") {
            $headers[$Matches[1]] = $Matches[2]
        }
    }

    # Check for WebSocket upgrade
    if ($headers["Upgrade"] -ine "websocket" -or -not $headers["Sec-WebSocket-Key"]) {
        $resp = "HTTP/1.1 200 OK`r`nContent-Length: 2`r`n`r`nOK"
        $stream.Write([System.Text.Encoding]::ASCII.GetBytes($resp), 0, $resp.Length)
        $client.Close()
        Log "[-] Not a WebSocket request"
        continue
    }

    # WebSocket handshake
    $accept = Get-WsAccept $headers["Sec-WebSocket-Key"]
    $resp = "HTTP/1.1 101 Switching Protocols`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Accept: $accept`r`n`r`n"
    $stream.Write([System.Text.Encoding]::ASCII.GetBytes($resp), 0, $resp.Length)
    Log "[+] WebSocket upgraded"

    # Handle client commands
    while ($client.Connected) {
        $frame = Read-WsFrame $stream
        if ($null -eq $frame.data) {
            Log "[-] Client disconnected"
            break
        }

        if ($frame.op -eq 8) {  # Close frame
            break
        }

        if ($frame.op -ne 1) {  # Text expected for commands
            continue
        }

        $cmd = [System.Text.Encoding]::UTF8.GetString($frame.data)

        if ($cmd.StartsWith("CONNECT:")) {
            $addr = $cmd.Substring(8)
            $parts = $addr -split ":"
            $dHost = $parts[0]
            $dPort = [int]$parts[1]

            Log "[*] CONNECT $addr"

            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $tcp.Connect($dHost, $dPort)
                $ns = $tcp.GetStream()

                Send-WsText $stream "OK"
                Log "[+] Tunnel open: $addr"

                # Relay data bidirectionally
                $tcpBuf = New-Object byte[] 8192
                $idle = 0
                $done = $false

                while (-not $done -and $client.Connected -and $tcp.Connected) {
                    $didWork = $false

                    # TCP -> WebSocket
                    if ($ns.DataAvailable) {
                        try {
                            $n = $ns.Read($tcpBuf, 0, $tcpBuf.Length)
                            if ($n -gt 0) {
                                $chunk = New-Object byte[] $n
                                [Array]::Copy($tcpBuf, $chunk, $n)
                                Send-WsBinary $stream $chunk
                                $didWork = $true
                                $idle = 0
                            }
                            else { $done = $true }
                        } catch { $done = $true }
                    }

                    # WebSocket -> TCP
                    if ($client.Available -gt 0) {
                        $frame = Read-WsFrame $stream 100
                        if ($null -ne $frame.data) {
                            if ($frame.op -eq 2 -and $frame.data.Length -gt 0) {
                                # Binary data
                                $ns.Write($frame.data, 0, $frame.data.Length)
                                $didWork = $true
                                $idle = 0
                            }
                            elseif ($frame.op -eq 1) {
                                # Text command
                                $txt = [System.Text.Encoding]::UTF8.GetString($frame.data)
                                if ($txt -eq "CLOSE") { $done = $true }
                            }
                            elseif ($frame.op -eq 8) {
                                $done = $true
                            }
                        }
                    }

                    if (-not $didWork) {
                        $idle++
                        if ($idle -gt 300) { $done = $true }  # 30s idle timeout
                        Start-Sleep -Milliseconds 10
                    }
                }

                $tcp.Close()
                Log "[+] Closed: $addr"

            } catch {
                Log "[-] Connection failed: $addr - $_"
                Send-WsText $stream "ERROR:$_"
            }
        }
        elseif ($cmd -eq "PING") {
            Send-WsText $stream "PONG"
        }
    }

    $client.Close()
    Log "[-] Client session ended"
}
