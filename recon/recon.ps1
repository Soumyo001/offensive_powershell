# Set output file path
$OutFile = "$env:USERPROFILE\Desktop\System_Report.txt"

# Get hardware info
Get-ComputerInfo | Out-File -Append $OutFile

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

# Get public IP address
$PublicIP = (Invoke-RestMethod -Uri "https://api.ipify.org")
Write-Output "Public IP Address: $PublicIP" | Out-File -Append $OutFile

# Get extended location/network info via public IP
$geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$PublicIP"

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

# Generate Google Maps HTML
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
    <!-- Uncomment the following iframe only if you have a Google Maps Embed API key -->
    <!--
    <iframe width='600' height='450' style='border:0'
        loading='lazy' allowfullscreen
        src='https://www.google.com/maps/embed/v1/view?key=YOUR_API_KEY&center=$lat,$lon&zoom=12'>
    </iframe>
    -->
</body>
</html>
"@
$HtmlPath = "$env:USERPROFILE\Desktop\DeviceLocation.html"
$HtmlContent | Out-File -Encoding utf8 $HtmlPath

Write-Output "System report created on your Desktop as System_Report.txt"
Write-Output "Google Maps location HTML created on your Desktop as DeviceLocation.html"
