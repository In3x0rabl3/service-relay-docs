<#
.SYNOPSIS
    Port forwarder - Target side. Listens locally, forwards over WebSocket to Host.
.PARAMETER ListenPort
    Port to listen on locally (default: 1080)
.PARAMETER Host
    Host WebSocket server address (e.g., 192.168.1.100:8080)
#>
param(
    [int]$ListenPort = 1080,
    [Parameter(Mandatory=$true)]
    [string]$HostAddr
)

$ErrorActionPreference = "Stop"

function Log($msg) {
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $msg"
}

$parts = $HostAddr -split ":"
$hostName = $parts[0]
$hostPort = if ($parts.Length -gt 1) { [int]$parts[1] } else { 8080 }

Write-Host ""
Write-Host "=== Port Forward (Target) ===" -ForegroundColor Cyan
Write-Host "Listen: 0.0.0.0:$ListenPort"
Write-Host "Forward to Host: ${hostName}:${hostPort}"
Write-Host ""

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $ListenPort)
$listener.Start()
Log "Listening on 0.0.0.0:$ListenPort..."

while ($true) {
    Log "Waiting for connection..."
    $localClient = $listener.AcceptTcpClient()
    Log "Local connection accepted"

    try {
        $ws = New-Object System.Net.WebSockets.ClientWebSocket
        $cts = New-Object System.Threading.CancellationTokenSource
        $uri = [Uri]"ws://${hostName}:${hostPort}/"

        Log "Connecting to $uri..."
        $ws.ConnectAsync($uri, $cts.Token).GetAwaiter().GetResult() | Out-Null
        Log "Connected to Host"

        $localStream = $localClient.GetStream()
        $localBuffer = New-Object byte[] 65536
        $wsBuffer = New-Object byte[] 65536
        $wsSegment = New-Object System.ArraySegment[byte] -ArgumentList @(,$wsBuffer)

        $pendingWsReceive = $null
        $pendingLocalRead = $null

        Log "Relaying..."

        while ($localClient.Connected -and $ws.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            if ($null -eq $pendingLocalRead) {
                $pendingLocalRead = $localStream.ReadAsync($localBuffer, 0, $localBuffer.Length)
            }
            if ($null -eq $pendingWsReceive) {
                $pendingWsReceive = $ws.ReceiveAsync($wsSegment, $cts.Token)
            }

            $tasks = @($pendingLocalRead, $pendingWsReceive)
            $completed = [System.Threading.Tasks.Task]::WaitAny($tasks, 100)

            if ($completed -eq 0) {
                try {
                    $n = $pendingLocalRead.GetAwaiter().GetResult()
                    $pendingLocalRead = $null
                    if ($n -gt 0) {
                        $chunk = New-Object byte[] $n
                        [Array]::Copy($localBuffer, $chunk, $n)
                        $segment = New-Object System.ArraySegment[byte] -ArgumentList @(,$chunk)
                        $ws.SendAsync($segment, [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $cts.Token).GetAwaiter().GetResult() | Out-Null
                    } else { break }
                } catch { break }
            }
            elseif ($completed -eq 1) {
                try {
                    $result = $pendingWsReceive.GetAwaiter().GetResult()
                    $pendingWsReceive = $null
                    if ($result.Count -gt 0 -and $result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Binary) {
                        $localStream.Write($wsBuffer, 0, $result.Count)
                        $localStream.Flush()
                    }
                    elseif ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) { break }
                } catch { break }
            }
        }

        $ws.Dispose()
        $localClient.Close()
        Log "Connection closed"
    }
    catch {
        Log "ERROR: $_"
        try { $localClient.Close() } catch {}
    }
}
