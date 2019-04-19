$Date = Get-Date
$DateStr = '{0:yyyy.MM.dd}' -f $Date
$TimeStr = (Get-Date).ToShortTimeString()
$Description = $DateStr + " " + $TimeStr

$DateFrom = (Get-Date).AddDays(-1)
Get-EventLog -LogName Security -EntryType FailureAudit -InstanceId 4625 -After $DateFrom | Format-List > C:\ip-security\4625.txt
Get-Content C:\ip-security\4625.txt | Where-Object { $_.Contains("Source Network Address:")} | Sort-Object > C:\ip-security\4625IPsort.txt

$LastIP = "1.2.3.4"
$IPs = "00000,-----" + "," + "`r`n"
$RuleName = "AttackerIP-" + $LastIP

netsh.exe advfirewall firewall delete rule name=$RuleName
netsh.exe advfirewall firewall add rule name=$RuleName dir=in action=block localip=any remoteip=$LastIP description=$Description profile=any interfacetype=any
netsh.exe advfirewall firewall add rule name=$RuleName dir=out action=block localip=any remoteip=$LastIP description=$Description profile=any interfacetype=any

Get-Content C:\ip-security\4625IPsort.txt | ForEach-Object {
  if($_ -match $regex){
    $Sor = $_
    $Ip = $Sor.Substring(46,($Sor.length-46))
    if($Ip -ne $LastIp) {
      $IPs = $IPs + $IpNumber.ToString("00000") + "," + $LastIp + "," + "`r`n"
      if($IpNumber -ge 20) {
        $RuleName = "AttackerIP-" + $LastIP
        netsh.exe advfirewall firewall delete rule name=$RuleName
        #$RuleName
        netsh.exe advfirewall firewall add rule name=$RuleName dir=in action=block localip=any remoteip=$LastIP description=$Description profile=any interfacetype=any
        #$RuleName + " Input rule"
        netsh.exe advfirewall firewall add rule name=$RuleName dir=out action=block localip=any remoteip=$LastIP description=$Description profile=any interfacetype=any
        #$RuleName + " Output rule"
      }
      $LastIp = $Ip
      $IpNumber = 1
    }
    else {
      $IpNumber = $IpNumber + 1
    }
  }
}
$Ips > C:\ip-security\AttackerIps.txt
