<#
.SYNOPSIS
    Port forwarder - Host side. Accepts WebSocket and forwards to local port (e.g., SOCKS on 1080).
.PARAMETER WsPort
    WebSocket listen port (default: 8080)
.PARAMETER LocalPort
    Local port to forward to (default: 1080)
#>
param(
    [int]$WsPort = 8080,
    [int]$LocalPort = 1080
)

$ErrorActionPreference = "Stop"

function Log($msg) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg"
}

function Get-WsAccept($key) {
    $guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    $sha = [System.Security.Cryptography.SHA1]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($key + $guid))
    return [Convert]::ToBase64String($hash)
}

function Send-WsBinary($stream, [byte[]]$data) {
    $frame = New-Object System.Collections.Generic.List[byte]
    $frame.Add(0x82)
    if ($data.Length -lt 126) {
        $frame.Add([byte]$data.Length)
    }
    elseif ($data.Length -lt 65536) {
        $frame.Add(126)
        $frame.Add([byte](($data.Length -shr 8) -band 0xFF))
        $frame.Add([byte]($data.Length -band 0xFF))
    }
    else {
        $frame.Add(127)
        for ($i = 7; $i -ge 0; $i--) {
            $frame.Add([byte](($data.Length -shr ($i * 8)) -band 0xFF))
        }
    }
    $frame.AddRange($data)
    $stream.Write($frame.ToArray(), 0, $frame.Count)
    $stream.Flush()
}

function Read-WsFrameAsync($stream, $buffer) {
    $header = New-Object byte[] 2
    $headerTask = $stream.ReadAsync($header, 0, 2)
    return @{ HeaderTask = $headerTask; Header = $header; Stream = $stream }
}

function Complete-WsFrameRead($state) {
    try {
        $n = $state.HeaderTask.GetAwaiter().GetResult()
        if ($n -lt 2) { return $null }
        $header = $state.Header
        $stream = $state.Stream
        $opcode = $header[0] -band 0x0F
        if ($opcode -eq 8) { return $null }
        $masked = ($header[1] -band 0x80) -ne 0
        $length = $header[1] -band 0x7F
        if ($length -eq 126) {
            $ext = New-Object byte[] 2
            $stream.Read($ext, 0, 2) | Out-Null
            $length = ([int]$ext[0] -shl 8) -bor [int]$ext[1]
        }
        elseif ($length -eq 127) {
            $ext = New-Object byte[] 8
            $stream.Read($ext, 0, 8) | Out-Null
            $length = 0
            for ($i = 0; $i -lt 8; $i++) { $length = ($length -shl 8) -bor [int]$ext[$i] }
        }
        $mask = $null
        if ($masked) { $mask = New-Object byte[] 4; $stream.Read($mask, 0, 4) | Out-Null }
        if ($length -eq 0) { return [byte[]]@() }
        $payload = New-Object byte[] $length
        $total = 0
        while ($total -lt $length) {
            $r = $stream.Read($payload, $total, $length - $total)
            if ($r -le 0) { break }
            $total += $r
        }
        if ($masked) { for ($i = 0; $i -lt $payload.Length; $i++) { $payload[$i] = $payload[$i] -bxor $mask[$i % 4] } }
        return $payload
    } catch { return $null }
}

Write-Host ""
Write-Host "=== Port Forward (Host) ===" -ForegroundColor Cyan
Write-Host "WebSocket: 0.0.0.0:$WsPort"
Write-Host "Forward to local: 127.0.0.1:$LocalPort"
Write-Host ""

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $WsPort)
$listener.Start()
Log "Listening for WebSocket on 0.0.0.0:$WsPort..."

while ($true) {
    Log "Waiting for connection..."
    $wsClient = $listener.AcceptTcpClient()
    $clientIP = $wsClient.Client.RemoteEndPoint.ToString()
    Log "Connection from $clientIP"

    try {
        $wsStream = $wsClient.GetStream()
        $buffer = New-Object byte[] 4096
        $read = $wsStream.Read($buffer, 0, 4096)
        $request = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        $lines = $request -split "`r`n"
        $headers = @{}
        foreach ($line in $lines) {
            if ($line -match "^([^:]+):\s*(.*)$") { $headers[$Matches[1].ToLower()] = $Matches[2] }
        }

        if ($headers["upgrade"] -ne "websocket") {
            Log "Not WebSocket, rejected"
            $wsClient.Close()
            continue
        }

        $key = $headers["sec-websocket-key"]
        $accept = Get-WsAccept $key
        $response = "HTTP/1.1 101 Switching Protocols`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Accept: $accept`r`n`r`n"
        $responseBytes = [System.Text.Encoding]::ASCII.GetBytes($response)
        $wsStream.Write($responseBytes, 0, $responseBytes.Length)
        $wsStream.Flush()
        Log "WebSocket upgraded"

        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $tcp.Connect("127.0.0.1", $LocalPort)
            Log "Connected to local 127.0.0.1:$LocalPort"
        } catch {
            Log "ERROR: Cannot connect to 127.0.0.1:$LocalPort - $_"
            $wsClient.Close()
            continue
        }

        $tcpStream = $tcp.GetStream()
        $tcpBuffer = New-Object byte[] 65536
        $pendingWsRead = $null
        $pendingTcpRead = $null

        Log "Relaying..."

        while ($wsClient.Connected -and $tcp.Connected) {
            if ($null -eq $pendingWsRead) { $pendingWsRead = Read-WsFrameAsync $wsStream $null }
            if ($null -eq $pendingTcpRead) { $pendingTcpRead = $tcpStream.ReadAsync($tcpBuffer, 0, $tcpBuffer.Length) }

            $tasks = @($pendingWsRead.HeaderTask, $pendingTcpRead)
            $completed = [System.Threading.Tasks.Task]::WaitAny($tasks, 100)

            if ($completed -eq 0) {
                $data = Complete-WsFrameRead $pendingWsRead
                $pendingWsRead = $null
                if ($null -ne $data -and $data.Length -gt 0) {
                    $tcpStream.Write($data, 0, $data.Length)
                    $tcpStream.Flush()
                } elseif ($null -eq $data) { break }
            }
            elseif ($completed -eq 1) {
                try {
                    $n = $pendingTcpRead.GetAwaiter().GetResult()
                    $pendingTcpRead = $null
                    if ($n -gt 0) {
                        $chunk = New-Object byte[] $n
                        [Array]::Copy($tcpBuffer, $chunk, $n)
                        Send-WsBinary $wsStream $chunk
                    } else { break }
                } catch { break }
            }
        }

        $tcp.Close()
        $wsClient.Close()
        Log "Connection closed"
    } catch {
        Log "ERROR: $_"
        try { $wsClient.Close() } catch {}
    }
}
