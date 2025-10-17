$NetReport = "$env:USERPROFILE\Documents\network_report_detailed.txt"
"" | Set-Content $NetReport

function Append-Section($title) { "`n==== $title ====`n" | Out-File -Append $NetReport }

# 1. 802.1x Authentication State
Append-Section "802.1x Authentication State (LAN & Wi-Fi)"
try {
    netsh lan show interfaces | Out-File -Append $NetReport
    netsh wlan show interfaces | Out-File -Append $NetReport
} catch {}

# 2. NLA (Network Level Authentication) & RDP Settings
Append-Section "RDP/NLA Settings"
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\'
    "Remote Desktop Enabled: $([bool](-not $rdp.fDenyTSConnections))" | Out-File -Append $NetReport
    $nla = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    "NLA Required: $([bool]$nla.UserAuthentication)" | Out-File -Append $NetReport
} catch {}

Append-Section "RDP/3389 Firewall Rules"
Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*Remote Desktop*' -or $_.Direction -eq "Inbound" -and $_.LocalPort -eq 3389 } | 
    Select DisplayName, Enabled, Direction, Action, Profile | Out-File -Append $NetReport

# 3. LLMNR & NetBIOS over TCP/IP
Append-Section "LLMNR/NetBIOS Name Resolution Settings"
Get-DnsClient | Select InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress, UseMulticast | Out-File -Append $NetReport
Get-WmiObject Win32_NetworkAdapterConfiguration | Select Description, TcpipNetbiosOptions | Out-File -Append $NetReport

# 4. AD Domain, Trusts, DCs, Secure Channel
Append-Section "Active Directory Domain & Trust Details"
$cs = Get-WmiObject Win32_ComputerSystem
"Domain: $($cs.Domain)" | Out-File -Append $NetReport
"Part Of Domain: $($cs.PartOfDomain)" | Out-File -Append $NetReport
try {
    nltest /dclist:$($cs.Domain) | Out-File -Append $NetReport
    nltest /trusted_domains | Out-File -Append $NetReport
    nltest /sc_query:$($cs.Domain) | Out-File -Append $NetReport
} catch {}

# 5. WINS Servers
Append-Section "WINS Servers"
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.WINSEnableProxy -eq $true -or $_.WINSPrimaryServer -or $_.WINSSecondaryServer} |
    Select Description, WINSPrimaryServer, WINSSecondaryServer, WINSEnableLMHostsLookup | Out-File -Append $NetReport

# 6. WLAN Capabilities/Blacklists
Append-Section "WLAN Capabilities & Blacklists"
try {
    netsh wlan show drivers | Out-File -Append $NetReport
    netsh wlan show filters | Out-File -Append $NetReport
} catch {}

# 7. DHCP Options (Extra)
Append-Section "DHCP Options (if known)"
Get-NetIPConfiguration | ForEach-Object {
    "Adapter: $($_.InterfaceAlias)"
    "DHCP Server: $($_.DhcpServer.ServerAddresses -join ', ')"
    "DHCP Enabled: $($_.DhcpEnabled)"
    "DNS Servers: $($_.DNSServer.ServerAddresses -join ', ')"
    "Gateway: $($_.IPv4DefaultGateway.NextHop)"
    "DNS Suffix: $($_.DnsSuffix)"
    ""
} | Out-File -Append $NetReport

# 8. IP Helper API Info (Tunnels/endpoints)
Append-Section "Tunnel/IPv6 Transition Interfaces"
Get-NetIPInterface | Where-Object {$_.ConnectionState -eq "Connected" -and $_.InterfaceAlias -match "(ISATAP|Teredo|6to4|Tunnel)"} | 
    Select InterfaceAlias, InterfaceIndex, AddressFamily, ConnectionState | Out-File -Append $NetReport

# 9. NAT/Port-Forwarding Rules
Append-Section "NAT/Port-forwarding Configurations (if enabled)"
try {
    Get-NetNat | Out-File -Append $NetReport
    Get-NetNatSession | Out-File -Append $NetReport
} catch {}

# 10. Saved Credentials (for network resources)
Append-Section "Saved Credentials"
cmdkey /list | Out-File -Append $NetReport

# 11. WSL Networking State
Append-Section "WSL Networking State"
if (Get-Service -Name LxssManager -ErrorAction SilentlyContinue) {
    "WSL is installed:" | Out-File -Append $NetReport
    try { netsh interface show interface | findstr /I wsl | Out-File -Append $NetReport } catch {}
}

# 12. Bluetooth PAN and Paired Devices
Append-Section "Bluetooth PAN & Devices"
try {
    Get-PnpDevice -Class Bluetooth | Select Status, Class, FriendlyName, InstanceId | Out-File -Append $NetReport
} catch {}

# 13. Multicast Memberships (SSDP, mDNS, etc.)
Append-Section "Multicast Memberships"
try {
    netsh interface ipv4 show joins | Out-File -Append $NetReport
    netsh interface ipv6 show joins | Out-File -Append $NetReport
} catch {}

# 14. AD DNS Zones / SRV Records
Append-Section "AD DNS Zones / SRV Records (if available)"
if ($cs.PartOfDomain) {
    try {
        nslookup -type=SRV _ldap._tcp.$($cs.Domain) | Out-File -Append $NetReport
        nslookup -type=SRV _kerberos._tcp.$($cs.Domain) | Out-File -Append $NetReport
    } catch {}
}

# 15. Network Performance History
Append-Section "Network Performance/Adapter Events (last 50, dropped/disconnected only)"
try {
    Get-WinEvent -LogName System -MaxEvents 100 |
        Where-Object { $_.Id -in 27,32,10400..10499 } |
        Select TimeCreated, Id, Message |
        Out-File -Append $NetReport
} catch {}

# -- Add previous essentials (TCP, ARP, DNS, Wi-Fi, Proxies, etc.) here as desired; see your previous scripts. --

Write-Output "Detailed network report written to $NetReport"
