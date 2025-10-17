param(
    [string]$NetReport
)

function AppendSection($title) { "`n==== $title ====`n" | Out-File -Append $NetReport }

# 802.1x Authentication State (LAN & Wi-Fi)
AppendSection "802.1x Authentication State (LAN & Wi-Fi)"
try {
    netsh lan show interfaces | Out-File -Append $NetReport
    netsh wlan show interfaces | Out-File -Append $NetReport
} catch{}

# Wi-Fi Profiles & Passwords
AppendSection "Wi-Fi Profiles & Passwords"
$wifi_profiles = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object {
    $_.ToString().Split(":")[1].Trim()
}
foreach ($ssid in $wifi_profiles) {
    $wifipw = netsh wlan show profile name="$ssid" key=clear | Select-String "Key Content"
    $pw = if ($wifipw) { $wifipw.ToString().Split(":")[1].Trim() } else { "[NO PASSWORD SAVED]" }
    "SSID: $ssid - Password: $pw" | Out-File -Append $NetReport
}

# NLA & RDP Settings
AppendSection "RDP/NLA Settings"
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\'
    "Remote Desktop Enabled: $([bool](-not $rdp.fDenyTSConnections))" | Out-File -Append $NetReport
    $nla = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    "NLA Required: $([bool]$nla.UserAuthentication)" | Out-File -Append $NetReport
} catch{}

AppendSection "RDP/3389 Firewall Rules"
Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*Remote Desktop*' -or $_.Direction -eq "Inbound" -and $_.LocalPort -eq 3389 } | 
    Select-Object DisplayName, Enabled, Direction, Action, Profile | Out-File -Append $NetReport

# Active Firewall Profiles and Rules
AppendSection "Active Firewall Profiles and Rules"
Get-NetFirewallProfile | Out-File -Append $NetReport
Get-NetFirewallRule | Select-Object DisplayName, Direction, Action, Enabled | Out-File -Append $NetReport

# LLMNR & NetBIOS over TCP/IP
AppendSection "LLMNR/NetBIOS Name Resolution Settings"
Get-DnsClient | Select-Object InterfaceAlias, ConnectionSpecificSuffix, RegisterThisConnectionsAddress, UseMulticast | Out-File -Append $NetReport
Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object Description, TcpipNetbiosOptions | Out-File -Append $NetReport

# AD Domain, Trusts, DCs, Secure Channel
AppendSection "Active Directory Domain & Trust Details"
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
AppendSection "WINS Servers"
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.WINSEnableProxy -eq $true -or $_.WINSPrimaryServer -or $_.WINSSecondaryServer} |
    Select-Object Description, WINSPrimaryServer, WINSSecondaryServer, WINSEnableLMHostsLookup | Out-File -Append $NetReport

# WLAN Capabilities & Blacklists
AppendSection "WLAN Capabilities & Blacklists"
try {
    netsh wlan show drivers | Out-File -Append $NetReport
    netsh wlan show filters | Out-File -Append $NetReport
} catch{}

# DHCP Lease History
AppendSection "DHCP Lease Info"
try {
    Get-DhcpServerv4Lease | Select-Object IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime | Out-File -Append $NetReport
} catch{
    "DHCP lease history not available (admin or DHCP role required)." | Out-File -Append $NetReport
}

# DHCP Options (Extra)
AppendSection "DHCP Options (if known)"
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
AppendSection "Tunnel/IPv6 Transition Interfaces"
Get-NetIPInterface | Where-Object {$_.ConnectionState -eq "Connected" -and $_.InterfaceAlias -match "(ISATAP|Teredo|6to4|Tunnel)"} | 
    Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, ConnectionState | Out-File -Append $NetReport

# NAT/Port-Forwarding Rules
AppendSection "NAT/Port-forwarding Configurations (if enabled)"
try {
    Get-NetNat | Out-File -Append $NetReport
    Get-NetNatSession | Out-File -Append $NetReport
} catch{
    "NAT services or class not available on this machine." | Out-File -Append $NetReport
}

# Saved Credentials
AppendSection "Saved Credentials"
cmdkey /list | Out-File -Append $NetReport

# WSL Networking State
AppendSection "WSL Networking State"
if (Get-Service -Name LxssManager -ErrorAction SilentlyContinue) {
    "WSL is installed:" | Out-File -Append $NetReport
    try { netsh interface show interface | findstr /I wsl | Out-File -Append $NetReport } catch{}
}

# Bluetooth PAN & Devices
AppendSection "Bluetooth PAN & Devices"
try {
    $bt = Get-PnpDevice -Class Bluetooth | Select-Object Status, Class, FriendlyName, InstanceId
    if ($bt) { $bt | Out-File -Append $NetReport }
    else { "No Bluetooth devices found." | Out-File -Append $NetReport }
} catch{
    "Bluetooth enumeration not supported or no devices found." | Out-File -Append $NetReport
}


# Multicast Memberships (SSDP, mDNS, etc.)
AppendSection "Multicast Memberships"
try {
    netsh interface ipv4 show joins | Out-File -Append $NetReport
    netsh interface ipv6 show joins | Out-File -Append $NetReport
} catch{}

# AD DNS Zones / SRV Records
AppendSection "AD DNS Zones / SRV Records (if available)"
if ($cs.PartOfDomain) {
    try {
        nslookup -type=SRV _ldap._tcp.$($cs.Domain) | Out-File -Append $NetReport
        nslookup -type=SRV _kerberos._tcp.$($cs.Domain) | Out-File -Append $NetReport
    } catch{}
}

# Network Performance History
AppendSection "Network Performance/Adapter Events (last 50, dropped/disconnected only)"
try {
    Get-WinEvent -LogName System -MaxEvents 100 |
        Where-Object { $_.Id -in 27,32,10400..10499 } |
        Select-Object TimeCreated, Id, Message |
        Out-File -Append $NetReport
} catch{}

# Interface Details
AppendSection "Network Interface Details"
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, PhysicalMediaType | Out-File -Append $NetReport

# IP Address Configuration
AppendSection "IP Address Configuration"
Get-NetIPAddress | Select-Object InterfaceAlias, AddressFamily, IPAddress, PrefixLength | Out-File -Append $NetReport

# Default Gateways
AppendSection "Default Gateways"
Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | Select-Object InterfaceAlias, NextHop | Out-File -Append $NetReport

# Public IP Address
AppendSection "Public IP Address"
try {
    (Invoke-RestMethod -Uri "https://api.ipify.org?format=text") | Out-File -Append $NetReport
} catch{ "Could not fetch public IP." | Out-File -Append $NetReport }

# ARP Table
AppendSection "ARP Table"
arp -a | Out-File -Append $NetReport

# Routing Table
AppendSection "Routing Table"
route print | Out-File -Append $NetReport

# DNS Servers & Search Domains
AppendSection "DNS Servers & Search Domains"
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses | Out-File -Append $NetReport

# DNS Cache
AppendSection "DNS Cache"
Get-DnsClientCache | Out-File -Append $NetReport

# Network Shares: mapped and open on this machine
AppendSection "Network Shares (Mapped Drives)"
Get-SmbMapping | Select-Object LocalPath, RemotePath, Status | Out-File -Append $NetReport
AppendSection "Open SMB Shares on Machine"
Get-SmbShare | Select-Object Name, Path, Description | Out-File -Append $NetReport

# Active Connections and Listening Services
AppendSection "TCP/UDP Active Connections"
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess | Out-File -Append $NetReport
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess | Out-File -Append $NetReport

AppendSection "Listening Ports and Bound Processes"
netstat -abno | Out-File -Append $NetReport

# System Proxy Settings
AppendSection "System Proxy Settings"
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Select-Object ProxyServer, ProxyEnable | Out-File -Append $NetReport

# VPN Configurations
AppendSection "VPN Configurations"
try {
    Get-VpnConnection | Select-Object Name, ServerAddress, AllUserConnection, AuthenticationMethod, TunnelType | Out-File -Append $NetReport
} catch{ "No VPN profiles found or insufficient rights." | Out-File -Append $NetReport }

# Remote Access Tools (detection)
AppendSection "Remote Access Tools (Detection)"
"RDP Sessions:" | Out-File -Append $NetReport
query user | Out-File -Append $NetReport
(Get-Process | Where-Object {$_.Name -match "teamviewer|anydesk|vnc|logmein"} | Select-Object Name, Path, Id) | Out-File -Append $NetReport

# Network Adapter Driver Info
AppendSection "Network Adapter Driver Info"
Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter } | 
Select-Object Name, AdapterType, Manufacturer, DriverVersion, MACAddress | Out-File -Append $NetReport

# Network Event Logs: connections/authentications
AppendSection "Network Event Logs (Last 50 Logon Events)"
try {
    Get-WinEvent -LogName Security -MaxEvents 50 -FilterXPath "*[System[(EventID=4624) or (EventID=4634) or (EventID=4625)]]" | 
    Select-Object TimeCreated, Id, Message | Out-File -Append $NetReport
} catch{}

# NetBIOS info, domain/workgroup, local shares
AppendSection "NetBIOS & Workgroup Info"
nbtstat -n | Out-File -Append $NetReport
(Get-WmiObject Win32_ComputerSystem | Select-Object Domain, Workgroup, PartOfDomain) | Out-File -Append $NetReport
AppendSection "Enumerated SMB Shares"
net view \\$env:COMPUTERNAME | Out-File -Append $NetReport

# Wireless Client Fingerprinting / Hosted Network
AppendSection "Wireless Clients (if Hosted Network/AP role)"
try {
    netsh wlan show hostednetwork | Out-File -Append $NetReport
} catch{}

Write-Output "Network report written to $NetReport"
