# Port Forward Target - listens locally, forwards to Host WS
param([int]$P=1080,[Parameter(Mandatory)][string]$H)
Add-Type -A System.Net.WebSockets
$hp=$H-split":";$hn=$hp[0];$wp=if($hp.Length-gt1){[int]$hp[1]}else{8080}
$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,$P)
$l.Start()
Write-Host "Listen 0.0.0.0:$P -> ws://${hn}:${wp}"
while(1){
$c=$l.AcceptTcpClient();$cs=$c.GetStream()
$ws=New-Object System.Net.WebSockets.ClientWebSocket
$ct=New-Object Threading.CancellationTokenSource
try{$ws.ConnectAsync([Uri]"ws://${hn}:${wp}/",$ct.Token).GetAwaiter().GetResult()|Out-Null}catch{$c.Close();continue}
$lb=New-Object byte[] 65536;$wb=New-Object byte[] 65536
$seg=New-Object ArraySegment[byte] -Arg @(,$wb)
$wt=$null;$lt=$null
while($c.Connected-and$ws.State-eq[Net.WebSockets.WebSocketState]::Open){
if(!$lt){$lt=$cs.ReadAsync($lb,0,65536)}
if(!$wt){$wt=$ws.ReceiveAsync($seg,$ct.Token)}
$done=[Threading.Tasks.Task]::WaitAny(@($lt,$wt),50)
if($done-eq0){try{$n=$lt.GetAwaiter().GetResult();$lt=$null
if($n-gt0){$ch=New-Object byte[] $n;[Array]::Copy($lb,$ch,$n)
$ws.SendAsync((New-Object ArraySegment[byte] -Arg @(,$ch)),[Net.WebSockets.WebSocketMessageType]::Binary,1,$ct.Token).GetAwaiter().GetResult()|Out-Null}
else{break}}catch{break}}
if($done-eq1){try{$r=$wt.GetAwaiter().GetResult();$wt=$null
if($r.Count-gt0-and$r.MessageType-eq[Net.WebSockets.WebSocketMessageType]::Binary){$cs.Write($wb,0,$r.Count);$cs.Flush()}
elseif($r.MessageType-eq[Net.WebSockets.WebSocketMessageType]::Close){break}}catch{break}}}
$ws.Dispose();$c.Close()}
