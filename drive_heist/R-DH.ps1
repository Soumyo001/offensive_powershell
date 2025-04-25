function Test-Admin{
    $CurrentUser = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    return $CurrentUser.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if(-not (Test-Admin)){
    Write-Host "This Script Requires Admin Previledges to update Widnows. Restarting..."
    Start-Process powershell -ArgumentList "-NoP -ep bypass -File $PSCommandPath" -Verb RunAs
    exit
}

Write-Host "Revoking Drive Sharing..."
Remove-SmbShare -Name "Windows Update" -Force

Write-Host "Revoking Firewall rule group..."
netsh advfirewall firewall set rule group="network discovery" new enable=no

Write-Host "Disabling file and print sharing..."
netsh firewall set service type=fileandprint mode=disable profile=all

Write-Host "Resetting registry settings..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name restrictnullsessacces -Value 1 -Force

Write-Host "Drive sharing revoked and firewall rules reset to default."