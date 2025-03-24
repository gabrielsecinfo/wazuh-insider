$IP_atacante = "192.168.18.100"
# Bloqueia o tráfego de entrada e saída do IP malicioso
New-NetFirewallRule -DisplayName "Bloqueio IP Malicioso" -Direction Inbound -Action Block -RemoteAddress $IP_atacante -Enabled True
New-NetFirewallRule -DisplayName "Bloqueio IP Malicioso" -Direction Outbound -Action Block -RemoteAddress $IP_atacante -Enabled True
Write-Host "IP $IP_atacante foi isolado"
