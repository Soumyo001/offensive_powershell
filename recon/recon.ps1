# Set output file path
$OutFile = "$env:USERPROFILE\Desktop\System_Report.txt"

# --- System Info ---
"==== CPU Information ====" | Out-File -Append $OutFile
Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Architecture | Out-File -Append $OutFile

# --- System Hardware - RAM ---
"==== RAM Information ====" | Out-File -Append $OutFile
Get-WmiObject Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Manufacturer, PartNumber, Speed, SerialNumber | Out-File -Append $OutFile
Get-WmiObject -Class Win32_PhysicalMemoryArray | Select-Object MemoryDevices | Out-File -Append $OutFile

# --- System Hardware - Disks ---
"==== Disk Drives and SMART Status ====" | Out-File -Append $OutFile
Get-WmiObject Win32_DiskDrive | Select-Object Model, InterfaceType, MediaType, Size, SerialNumber, Status | Out-File -Append $OutFile
Get-Disk | Get-StorageReliabilityCounter | Out-File -Append $OutFile

# --- System Hardware - GPU ---
"==== GPU Information ====" | Out-File -Append $OutFile
Get-WmiObject Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion, VideoProcessor | Out-File -Append $OutFile

# --- System Hardware - Motherboard & BIOS ---
"==== Motherboard & BIOS Information ====" | Out-File -Append $OutFile
Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber, Version | Out-File -Append $OutFile
Get-WmiObject Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer, SerialNumber, ReleaseDate | Out-File -Append $OutFile

# --- Network Details ---
"==== Network Adapters (All) ====" | Out-File -Append $OutFile
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Out-File -Append $OutFile

"==== Ethernet Link Speeds ====" | Out-File -Append $OutFile
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed | Out-File -Append $OutFile

"==== DHCP Lease Info (if DHCP role is present) ====" | Out-File -Append $OutFile
try { Get-DhcpServerv4Lease | Out-File -Append $OutFile } catch { "No local DHCP server or permissions issue" | Out-File -Append $OutFile }

"==== User Profiles and Groups ====" | Out-File -Append $OutFile
Get-WmiObject Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true} | Out-File -Append $OutFile

"==== List of Administrators ====" | Out-File -Append $OutFile
Get-LocalGroupMember -Group "Administrators" | Out-File -Append $OutFile

"==== Last Logon Times for Local Profiles ====" | Out-File -Append $OutFile
Get-WmiObject Win32_NetworkLoginProfile | Select-Object Name, LastLogon | Out-File -Append $OutFile

"==== Running Processes ====" | Out-File -Append $OutFile
Get-Process | Select-Object Name, Id, Path | Out-File -Append $OutFile

"==== Services (status/startup type) ====" | Out-File -Append $OutFile
Get-Service | Select-Object DisplayName, Status, StartType | Out-File -Append $OutFile

"==== Startup Programs ====" | Out-File -Append $OutFile
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User | Out-File -Append $OutFile

"==== Scheduled Tasks ====" | Out-File -Append $OutFile
 Get-ScheduledTask | Select-Object Actions, Author, Date, Description, TaskName, TaskPath, Triggers, SecurityDescriptor, URI, state
| Select-Object TaskName, State, Author | Out-File -Append $OutFile

"==== Recent System Errors/Warnings ====" | Out-File -Append $OutFile
Get-EventLog -LogName System -EntryType Error, Warning -Newest 50 | Out-File -Append $OutFile

"==== Windows Updates Status ====" | Out-File -Append $OutFile
Get-HotFix | Out-File -Append $OutFile

"==== Battery Information (if present) ====" | Out-File -Append $OutFile
Get-WmiObject Win32_Battery | Out-File -Append $OutFile

"==== Audio Devices ====" | Out-File -Append $OutFile
Get-WmiObject Win32_SoundDevice | Out-File -Append $OutFile

"==== Printers ====" | Out-File -Append $OutFile
Get-WmiObject Win32_Printer | Out-File -Append $OutFile

# --- OS Licensing and Activation State ---
"==== OS Licensing ====" | Out-File -Append $OutFile
Get-WmiObject SoftwareLicensingProduct | Where-Object { $_.PartialProductKey } | Select-Object Name, LicenseStatus | Out-File -Append $OutFile

# --- Security: Firewall, BitLocker, Device Encryption ---
"==== Firewall Status ====" | Out-File -Append $OutFile
Get-NetFirewallProfile | Select-Object Name, Enabled | Out-File -Append $OutFile

"==== BitLocker Status ====" | Out-File -Append $OutFile
Get-BitLockerVolume | Out-File -Append $OutFile

# --- Connected USB Devices ---
"==== Connected USB Devices (past/present) ====" | Out-File -Append $OutFile
Get-WmiObject Win32_USBControllerDevice | ForEach-Object{
    [WMI]$_.Dependent
} | Out-File -Append $OutFile

# Get installed software
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Out-File -Append $OutFile

# Get MAC addresses
Get-NetAdapter | Select-Object Name, MacAddress | Out-File -Append $OutFile

# Get private/local IP addresses
Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Virtual*" } | Select-Object IPAddress | Out-File -Append $OutFile

# Get current username
Write-Output "Username: $env:USERNAME" | Out-File -Append $OutFile

# Get Antivirus status (Windows Defender)
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled | Out-File -Append $OutFile

# --- Network & Location Info ---
$PublicIP = (Invoke-RestMethod -Uri "https://api.ipify.org")
Write-Output "Public IP Address: $PublicIP" | Out-File -Append $OutFile

$geo = Invoke-RestMethod -Uri "http://ip-api.com/json/" -UseBasicParsing

$locationInfo = @"
Country:      $($geo.country)
CountryCode:  $($geo.countryCode)
Region:       $($geo.region)
RegionName:   $($geo.regionName)
City:         $($geo.city)
ZIP:          $($geo.zip)
Latitude:     $($geo.lat)
Longitude:    $($geo.lon)
Timezone:     $($geo.timezone)
ISP:          $($geo.isp)
Org:          $($geo.org)
AS:           $($geo.as)
Query IP:     $($geo.query)
"@
$locationInfo | Out-File -Append $OutFile

"Wi-Fi SSIDs and Passwords:" | Out-File -Append $OutFile
$profiles = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object {
    $_.ToString().Split(":")[1].Trim()
}
foreach ($name in $profiles) {
    $wifiInfo = netsh wlan show profile name="$name" key=clear
    $passwordLine = $wifiInfo | Select-String "Key Content"
    if ($passwordLine) {
        $password = $passwordLine.ToString().Split(":")[1].Trim()
    } else {
        $password = "[NO PASSWORD SAVED]"
    }
    "$name : $password" | Out-File -Append $OutFile
}

# --- Google Maps HTML ---
$lat = $geo.lat
$lon = $geo.lon
$MapsUrl = "https://www.google.com/maps/search/?api=1&query=$lat,$lon"

$HtmlContent = @"
<html>
<head>
    <title>Google Maps Location</title>
</head>
<body>
    <h2>Device Location on Google Maps</h2>
    <p>Country: $($geo.country)<br>
    Region: $($geo.regionName)<br>
    City: $($geo.city)<br>
    ZIP: $($geo.zip)<br>
    Latitude: $lat<br>
    Longitude: $lon<br></p>
    <p><a href='$MapsUrl' target='_blank'>Open Google Maps</a></p>
</body>
</html>
"@
$HtmlPath = "$env:USERPROFILE\Desktop\DeviceLocation.html"
$HtmlContent | Out-File -Encoding utf8 $HtmlPath

Write-Output "System report created on your Desktop as System_Report.txt"
Write-Output "Google Maps location HTML created on your Desktop as DeviceLocation.html"
