$NetReport = "$env:USERPROFILE\Documents\network_report_full.txt"

function Append-Section($title) { "`n==== $title ====`n" | Out-File -Append $NetReport }

# 802.1x Authentication State (LAN & Wi-Fi)
Append-Section "802.1x Authentication State (LAN & Wi-Fi)"
try {
    netsh lan show interfaces | Out-File -Append $NetReport
    netsh wlan show interfaces | Out-File -Append $NetReport
} catch{}

# Wi-Fi Profiles & Passwords
Append-Section "Wi-Fi Profiles & Passwords"
$wifi_profiles = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object {
    $_.ToString().Split(":")[1].Trim()
}
foreach ($ssid in $wifi_profiles) {
    $wifipw = netsh wlan show profile name="$ssid" key=clear | Select-String "Key Content"
    $pw = if ($wifipw) { $wifipw.ToString().Split(":")[1].Trim() } else { "[NO PASSWORD SAVED]" }
    "SSID: $ssid - Password: $pw" | Out-File -Append $NetReport
}

# NLA & RDP Settings
Append-Section "RDP/NLA Settings"
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\'
    "Remote Desktop Enabled: $([bool](-not $rdp.fDenyTSConnections))" | Out-File -Append $NetReport
    $nla = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    "NLA Required: $([bool]$nla.UserAuthentication)" | Out-File -Append $NetReport
} catch{}

Append-Section "RDP/3389 Firewall Rules"
Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*Remote Desktop*' -or $_.Direction -eq "Inbound" -and $_.LocalPort -eq 3389 } | 
    Select-Object DisplayName, Enabled, Direction, Action, Profile | Out-File -Append $NetReport

# Active Firewall Profiles and Rules
Append-Section "Active Firewall Profiles and Rules"
Get-NetFirewallProfile | Out-File -Append $NetReport
Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled | Out-File -Append $NetReport

# LLMNR & NetBIOS over TCP/IP
Append-Section "LLMNR/NetBIOS Name Resolution Settings"
Get-DnsClient | Select-Object InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress, UseMulticast | Out-File -Append $NetReport
Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object Description, TcpipNetbiosOptions | Out-File -Append $NetReport

# AD Domain, Trusts, DCs, Secure Channel
Append-Section "Active Directory Domain & Trust Details"
$cs = Get-WmiObject Win32_ComputerSystem
"Domain: $($cs.Domain)" | Out-File -Append $NetReport
"Part Of Domain: $($cs.PartOfDomain)" | Out-File -Append $NetReport
try {
    nltest /dclist:$($cs.Domain) | Out-File -Append $NetReport
} catch{
    "No Domain Controller found or not on a domain." | Out-File -Append $NetReport
}
try { nltest /trusted_domains | Out-File -Append $NetReport } catch{ "Domain trusts not found (likely not a domain join)." | Out-File -Append $NetReport }
try {
    nltest /sc_query:$($cs.Domain) | Out-File -Append $NetReport
} catch{
    "Secure channel unavailable or RPC error (not a domain, or DC unreachable)." | Out-File -Append $NetReport
}

# WINS Servers
Append-Section "WINS Servers"
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.WINSEnableProxy -eq $true -or $_.WINSPrimaryServer -or $_.WINSSecondaryServer} |
    Select-Object Description, WINSPrimaryServer, WINSSecondaryServer, WINSEnableLMHostsLookup | Out-File -Append $NetReport

# WLAN Capabilities & Blacklists
Append-Section "WLAN Capabilities & Blacklists"
try {
    netsh wlan show drivers | Out-File -Append $NetReport
    netsh wlan show filters | Out-File -Append $NetReport
} catch{}

# DHCP Lease History
Append-Section "DHCP Lease Info"
try {
    Get-DhcpServerv4Lease | Select-Object IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime | Out-File -Append $NetReport
} catch{
    "DHCP lease history not available (admin or DHCP role required)." | Out-File -Append $NetReport
}

# DHCP Options (Extra)
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

# IP Helper API Info (Tunnels, IPv6)
Append-Section "Tunnel/IPv6 Transition Interfaces"
Get-NetIPInterface | Where-Object {$_.ConnectionState -eq "Connected" -and $_.InterfaceAlias -match "(ISATAP|Teredo|6to4|Tunnel)"} | 
    Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ConnectionState | Out-File -Append $NetReport

# NAT/Port-Forwarding Rules
Append-Section "NAT/Port-forwarding Configurations (if enabled)"
try {
    Get-NetNat | Out-File -Append $NetReport
    Get-NetNatSession | Out-File -Append $NetReport
} catch{
    "NAT services or class not available on this machine." | Out-File -Append $NetReport
}

# Saved Credentials
Append-Section "Saved Credentials"
cmdkey /list | Out-File -Append $NetReport

# WSL Networking State
Append-Section "WSL Networking State"
if (Get-Service -Name LxssManager -ErrorAction SilentlyContinue) {
    "WSL is installed:" | Out-File -Append $NetReport
    try { netsh interface show interface | findstr /I wsl | Out-File -Append $NetReport } catch{}
}

# Bluetooth PAN & Devices
Append-Section "Bluetooth PAN & Devices"
try {
    $bt = Get-PnpDevice -Class Bluetooth | Select-Object Status, Class, FriendlyName, InstanceId
    if ($bt) { $bt | Out-File -Append $NetReport }
    else { "No Bluetooth devices found." | Out-File -Append $NetReport }
} catch{
    "Bluetooth enumeration not supported or no devices found." | Out-File -Append $NetReport
}


# Multicast Memberships (SSDP, mDNS, etc.)
Append-Section "Multicast Memberships"
try {
    netsh interface ipv4 show joins | Out-File -Append $NetReport
    netsh interface ipv6 show joins | Out-File -Append $NetReport
} catch{}

# AD DNS Zones / SRV Records
Append-Section "AD DNS Zones / SRV Records (if available)"
if ($cs.PartOfDomain) {
    try {
        nslookup -type=SRV _ldap._tcp.$($cs.Domain) | Out-File -Append $NetReport
        nslookup -type=SRV _kerberos._tcp.$($cs.Domain) | Out-File -Append $NetReport
    } catch{}
}

# Network Performance History
Append-Section "Network Performance/Adapter Events (last 50, dropped/disconnected only)"
try {
    Get-WinEvent -LogName System -MaxEvents 100 |
        Where-Object { $_.Id -in 27,32,10400..10499 } |
        Select-Object TimeCreated, Id, Message |
        Out-File -Append $NetReport
} catch{}

# Interface Details
Append-Section "Network Interface Details"
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, PhysicalMediaType | Out-File -Append $NetReport

# IP Address Configuration
Append-Section "IP Address Configuration"
Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength | Out-File -Append $NetReport

# Default Gateways
Append-Section "Default Gateways"
Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | Select-Object InterfaceAlias, NextHop | Out-File -Append $NetReport

# Public IP Address
Append-Section "Public IP Address"
try {
    (Invoke-RestMethod -Uri "https://api.ipify.org?format=text") | Out-File -Append $NetReport
} catch{ "Could not fetch public IP." | Out-File -Append $NetReport }

# ARP Table
Append-Section "ARP Table"
arp -a | Out-File -Append $NetReport

# Routing Table
Append-Section "Routing Table"
route print | Out-File -Append $NetReport

# DNS Servers & Search Domains
Append-Section "DNS Servers & Search Domains"
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses | Out-File -Append $NetReport

# DNS Cache
Append-Section "DNS Cache"
Get-DnsClientCache | Out-File -Append $NetReport

# Network Shares: mapped and open on this machine
Append-Section "Network Shares (Mapped Drives)"
Get-SmbMapping | Select-Object LocalPath, RemotePath, Status | Out-File -Append $NetReport
Append-Section "Open SMB Shares on Machine"
Get-SmbShare | Select-Object Name, Path, Description | Out-File -Append $NetReport

# Active Connections and Listening Services
Append-Section "TCP/UDP Active Connections"
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Out-File -Append $NetReport
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Out-File -Append $NetReport

Append-Section "Listening Ports and Bound Processes"
netstat -abno | Out-File -Append $NetReport

# System Proxy Settings
Append-Section "System Proxy Settings"
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer, ProxyEnable | Out-File -Append $NetReport

# VPN Configurations
Append-Section "VPN Configurations"
try {
    Get-VpnConnection | Select-Object Name, ServerAddress, AllUserConnection, AuthenticationMethod, TunnelType | Out-File -Append $NetReport
} catch{ "No VPN profiles found or insufficient rights." | Out-File -Append $NetReport }

# Remote Access Tools (detection)
Append-Section "Remote Access Tools (Detection)"
"RDP Sessions:" | Out-File -Append $NetReport
query user | Out-File -Append $NetReport
(Get-Process | Where {$_.Name -match "teamviewer|anydesk|vnc|logmein"} | Select-Object Name, Path, Id) | Out-File -Append $NetReport

# Network Adapter Driver Info
Append-Section "Network Adapter Driver Info"
Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter } | 
Select-Object Name, AdapterType, Manufacturer, DriverVersion, MACAddress | Out-File -Append $NetReport

# Network Event Logs: connections/authentications
Append-Section "Network Event Logs (Last 50 Logon Events)"
try {
    Get-WinEvent -LogName Security -MaxEvents 50 -FilterXPath "*[System[(EventID=4624) or (EventID=4634) or (EventID=4625)]]" | 
    Select-Object TimeCreated, Id, Message | Out-File -Append $NetReport
} catch{}

# NetBIOS info, domain/workgroup, local shares
Append-Section "NetBIOS & Workgroup Info"
nbtstat -n | Out-File -Append $NetReport
(Get-WmiObject Win32_ComputerSystem | Select-Object Domain, Workgroup, PartOfDomain) | Out-File -Append $NetReport
Append-Section "Enumerated SMB Shares"
net view \\$env:COMPUTERNAME | Out-File -Append $NetReport

# Wireless Client Fingerprinting / Hosted Network
Append-Section "Wireless Clients (if Hosted Network/AP role)"
try {
    netsh wlan show hostednetwork | Out-File -Append $NetReport
} catch{}

Write-Output "Network report written to $NetReport"
