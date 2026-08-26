# Port Forward Host - WS server, forwards to local port
param([int]$W=8080,[int]$P=1080)
Add-Type -A System.Net.WebSockets
$l=[System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any,$W)
$l.Start()
Write-Host "WS:$W -> localhost:$P"
while(1){
$c=$l.AcceptTcpClient();$s=$c.GetStream()
$d=New-Object byte[] 4096;$n=$s.Read($d,0,4096)
$r=[Text.Encoding]::ASCII.GetString($d,0,$n)
$h=@{};$r-split"`r`n"|%{if($_-match"^([^:]+):\s*(.*)"){$h[$Matches[1].ToLower()]=$Matches[2]}}
if($h["upgrade"]-ne"websocket"){$c.Close();continue}
$k=$h["sec-websocket-key"]
$a=[Convert]::ToBase64String([Security.Cryptography.SHA1]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($k+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
$s.Write([Text.Encoding]::ASCII.GetBytes("HTTP/1.1 101 Switching Protocols`r`nUpgrade:websocket`r`nConnection:Upgrade`r`nSec-WebSocket-Accept:$a`r`n`r`n"),0,129+$a.Length)
$t=New-Object System.Net.Sockets.TcpClient("127.0.0.1",$P);$ts=$t.GetStream()
$tb=New-Object byte[] 65536;$wb=New-Object byte[] 65536
while($c.Connected-and$t.Connected){
if($c.Available-gt0){
$s.Read($wb,0,2)|Out-Null
$m=$wb[1]-band0x80;$ln=$wb[1]-band0x7F
if($ln-eq126){$e=New-Object byte[] 2;$s.Read($e,0,2)|Out-Null;$ln=([int]$e[0]-shl8)-bor$e[1]}
$mk=$null;if($m){$mk=New-Object byte[] 4;$s.Read($mk,0,4)|Out-Null}
if($ln-gt0){$pl=New-Object byte[] $ln;$s.Read($pl,0,$ln)|Out-Null
if($m){for($i=0;$i-lt$ln;$i++){$pl[$i]=$pl[$i]-bxor$mk[$i%4]}}
$ts.Write($pl,0,$ln);$ts.Flush()}}
if($ts.DataAvailable){$n=$ts.Read($tb,0,65536)
if($n-gt0){$f=New-Object Collections.Generic.List[byte];$f.Add(0x82)
if($n-lt126){$f.Add($n)}else{$f.Add(126);$f.Add(($n-shr8)-band0xFF);$f.Add($n-band0xFF)}
$f.AddRange($tb[0..($n-1)]);$s.Write($f.ToArray(),0,$f.Count)}}
Start-Sleep -M 5}
$t.Close();$c.Close()}
