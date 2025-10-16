$OutFile = "$env:USERPROFILE\Desktop\System_Report.txt"

"==== CPU Information ====" | Out-File -Append $OutFile
Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Architecture | Out-File -Append $OutFile

"==== RAM Information ====" | Out-File -Append $OutFile
Get-WmiObject Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Manufacturer, PartNumber, Speed, SerialNumber | Out-File -Append $OutFile
Get-WmiObject -Class Win32_PhysicalMemoryArray | Select-Object MemoryDevices | Out-File -Append $OutFile

"==== Disk Drives and SMART Status ====" | Out-File -Append $OutFile
Get-WmiObject Win32_DiskDrive | Select-Object Model, InterfaceType, MediaType, Size, SerialNumber, Status | Out-File -Append $OutFile
try { Get-Disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Out-File -Append $OutFile }catch {}

"==== GPU Information ====" | Out-File -Append $OutFile
Get-WmiObject Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion, VideoProcessor | Out-File -Append $OutFile

"==== Motherboard & BIOS Information ====" | Out-File -Append $OutFile
Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber, Version | Out-File -Append $OutFile
Get-WmiObject Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer, SerialNumber, ReleaseDate | Out-File -Append $OutFile

"==== Network Adapters (All) ====" | Out-File -Append $OutFile
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Out-File -Append $OutFile

"==== Ethernet Link Speeds ====" | Out-File -Append $OutFile
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed | Out-File -Append $OutFile

"==== DHCP Lease Info (if DHCP role is present) ====" | Out-File -Append $OutFile
try { Get-DhcpServerv4Lease | Out-File -Append $OutFile } catch { "No local DHCP server or permissions issue `n" | Out-File -Append $OutFile }

"==== User Profiles and Groups ====" | Out-File -Append $OutFile
Get-WmiObject Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true} | Out-File -Append $OutFile

"==== List of Administrators ====" | Out-File -Append $OutFile
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, SID | Out-File -Append $OutFile

"==== Last Logon Times for Local Profiles ====" | Out-File -Append $OutFile
Get-WmiObject Win32_NetworkLoginProfile | Select-Object Name, 
@{Name="LastLogon";Expression={ 
    if ($_.LastLogon) { 
        [System.Management.ManagementDateTimeConverter]::ToDateTime($_.LastLogon) 
    } else { 
        $null 
    } 
}},
@{Name="PasswordAge";Expression={ 
    if ($_.PasswordAge) { 
        $ticks = [int64]$_.PasswordAge.Split('.')[0]
        (New-TimeSpan -Ticks $ticks)
    } else { 
        $null 
    }
}},
@{Name="PasswordExpires";Expression={
    if ($_.PasswordExpires) {
        [System.Management.ManagementDateTimeConverter]::ToDateTime($_.PasswordExpires)
    } else {
        $null
    }
}}, CountryCode, Privileges | Out-File -Append $OutFile

"==== Running Processes ====" | Out-File -Append $OutFile
Get-Process | Select-Object Name, Id, Path | Out-File -Append $OutFile

"==== Startup Programs ====" | Out-File -Append $OutFile
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User | Out-File -Append $OutFile

"==== Recent System Errors/Warnings ====" | Out-File -Append $OutFile
Get-EventLog -LogName System -EntryType Error, Warning -Newest 50 |
    ForEach-Object { "[$($_.EntryType)] $($_.TimeGenerated) $($_.Source): $($_.Message)" } | Out-File -Append $OutFile

"==== Windows Updates Status ====" | Out-File -Append $OutFile
Get-HotFix | Out-File -Append $OutFile

"==== Battery Information (if present) ====" | Out-File -Append $OutFile
try{Get-WmiObject Win32_Battery | Out-File -Append $OutFile}catch{Write-Output "$_" | Out-File -Append $OutFile}

"==== Audio Devices ====" | Out-File -Append $OutFile
Get-WmiObject Win32_SoundDevice | Out-File -Append $OutFile

"==== Printers ====" | Out-File -Append $OutFile
Get-WmiObject Win32_Printer | Out-File -Append $OutFile

"==== OS Licensing ====" | Out-File -Append $OutFile
Get-WmiObject SoftwareLicensingProduct | Where-Object { $_.PartialProductKey } | Select-Object Name, LicenseStatus | Out-File -Append $OutFile

"==== Firewall Status ====" | Out-File -Append $OutFile
Get-NetFirewallProfile | Select-Object Name, Enabled | Out-File -Append $OutFile

"==== Connected USB Devices (past/present) ====" | Out-File -Append $OutFile
Get-WmiObject Win32_USBControllerDevice | ForEach-Object{
    try {
        $dev = [WMI]$_.Dependent
        "DeviceID: $($dev.DeviceID), Description: $($dev.Description), Manufacturer: $($dev.Manufacturer)"
    } catch {}
} | Out-File -Append $OutFile

"==== Detailed USB Device History ====" | Out-File $OutFile
$usbStorRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $usbStorRoot) {
    Get-ChildItem -Path $usbStorRoot | ForEach-Object {
        $deviceKey = $_.PSChildName
        $devicePath = Join-Path $usbStorRoot $deviceKey
        Get-ChildItem -Path $devicePath | ForEach-Object {
            $instance = $_.PSChildName
            $instancePath = Join-Path $devicePath $instance
            $props = Get-ItemProperty -Path $instancePath
            $output = @()
            $output += "Device: $deviceKey    Instance: $instance"
            $output += "FriendlyName   : $($props.FriendlyName)"
            $output += "Manufacturer   : $($props.Manufacturer)"
            $output += "SerialNumber   : $($instance)"
            $output += "Class          : $($props.Class)"
            $output += "DeviceDesc     : $($props.DeviceDesc)"
            $output += "VID/PID        : $(($deviceKey -split '&')[1,2] -join ', ')"
            # FirstInstallDate and LastArrivalDate (if present)
            if ($props.InstallDate)        { $output += "InstallDate    : $($props.InstallDate)" }
            if ($props.LastArrivalDate)    { $output += "LastArrivalDate: $($props.LastArrivalDate)" }
            # Write output block
            $output | Out-File -Append $OutFile
            "" | Out-File -Append $OutFile
        }
    }
}

# Get drive letters and volume basic info for all USB disk drives
Get-WmiObject Win32_DiskDrive | Where-Object { $_.InterfaceType -eq 'USB' } | ForEach-Object {
    $output = @()
    $output += "DeviceID      : $($_.DeviceID)"
    $output += "PNPDeviceID   : $($_.PNPDeviceID)"
    $output += "SerialNumber  : $($_.SerialNumber)"
    $output += "Description   : $($_.Model)"
    $output += "Manufacturer  : $($_.Manufacturer)"
    # VID & PID
    $vidpid = ($_.PNPDeviceID -split '\\')[1]
    $output += "VID/PID       : $vidpid"
    # Find partitions/volumes, get drive letter / label / FS
    $partitions = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($_.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
    foreach ($partition in $partitions) {
        $logical = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition"
        foreach ($l in $logical) {
            $output += "DriveLetter    : $($l.DeviceID)"
            $output += "VolumeLabel    : $($l.VolumeName)"
            $output += "FileSystem     : $($l.FileSystem)"
        }
    }
    # Write output block
    $output | Out-File -Append $OutFile
    "" | Out-File -Append $OutFile
}

# Optionally display all USB registry keys for deep forensics
$usbRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
if (Test-Path $usbRoot) {
    "==== Raw USB Registry Entries ====" | Out-File -Append $OutFile
    Get-ChildItem -Path $usbRoot | ForEach-Object {
        "Key: $($_.Name)" | Out-File -Append $OutFile
    }
}

# User context for USB insertion is not directly available, but recent arrivals/install may show currently active user in Windows event logs
"==== Recent USB Arrival Events (event logs) ====" | Out-File -Append $OutFile
Get-WinEvent -FilterHashtable @{LogName='System';ID=2003,2100,2102,2106,400,410,43} -MaxEvents 30 | ForEach-Object {
    "Time: $($_.TimeCreated), Message: $($_.Message)"
} | Out-File -Append $OutFile

# Get installed software
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Out-File -Append $OutFile

Get-NetAdapter | Select-Object Name, MacAddress | Out-File -Append $OutFile

Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Virtual*" } | Select-Object IPAddress | Out-File -Append $OutFile

Write-Output "Username: $env:USERNAME" | Out-File -Append $OutFile

# Get Antivirus status
$antiviruses = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
if ($antiviruses) {
    $antiviruses | ForEach-Object {
        "Name        : $($_.displayName)"
        "Product GUID: $($_.instanceGuid)"
        "State       : $($_.productState)"
        "Path        : $($_.pathToSignedProductExe)`n"
    } | Out-File -Append $OutFile
} else {
    "No antivirus products detected, or script must be run with Administrator privileges." | Out-File -Append $OutFile
}

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
